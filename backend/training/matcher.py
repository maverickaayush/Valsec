"""Learned mapping resolver and Ollama-powered classifier.

The resolver checks persistent learned_mappings for existing vendor/pattern pairs.
The classifier uses Ollama to propose schema field mappings for unknown lines,
following strict patterns: retry logic, JSON format mode, timeout scaling, and
NO configuration data sent externally.

Critical: AI proposes only. Operator approval is required before persistence.
Compliance verdicts remain 100% deterministic via rule evaluation.
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

import requests
from sqlalchemy.orm import Session

from config import settings
from models import LearnedMapping
from normalizer.schema import Confidence, MappingSource, NormalizedFinding


@dataclass(frozen=True)
class MappingMatch:
    """A learned mapping result supplied by the resolver."""
    schema_field: str
    field_value: Any

logger = logging.getLogger(__name__)

# Ollama configuration following existing patterns from analysis/ollama_client.py
_OLLAMA_BASE_URL = "http://localhost:11434"
_OLLAMA_TIMEOUT = round(30 * settings.SCAN_TIMEOUT_MULTIPLIER)  # 30s baseline, scaled
_MAX_RETRIES = 3
_RETRY_DELAY = 1  # seconds between retries


def _call_ollama(
    prompt: str,
    model: str = "qwen2.5:7b",
    format: str = "json",
    timeout_ms: int = 30000,
    max_retries: int = 3,
) -> Optional[str]:
    """Call Ollama API following existing retry/timeout patterns.

    This function implements the same integration pattern as analysis/ollama_client.py:
    - Retry logic (default 3 attempts)
    - JSON format mode for structured responses
    - Timeout scaling
    - No configuration data sent externally (only the specific CLI line)

    Args:
        prompt: The prompt to send to Ollama
        model: Model name (default: qwen2.5:7b for local inference)
        format: Response format (default: "json")
        timeout_ms: Timeout in milliseconds (default: 30000)
        max_retries: Maximum retry attempts (default: 3)

    Returns:
        The model's text response, or None on failure.
    """
    url = f"{_OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": format,
    }

    for attempt in range(max_retries):
        try:
            start = time.time()
            response = requests.post(
                url, json=payload, timeout=timeout_ms / 1000  # Convert to seconds
            )
            elapsed = time.time() - start

            if response.status_code == 200:
                data = response.json()
                response_text = data.get("response", "")
                logger.info(
                    f"Ollama responded in {elapsed:.2f}s (attempt {attempt + 1})"
                )
                return response_text
            else:
                logger.warning(
                    f"Ollama returned status {response.status_code} "
                    f"(attempt {attempt + 1}/{max_retries})"
                )

        except requests.exceptions.Timeout:
            logger.warning(
                f"Ollama timeout after {timeout_ms/1000:.1f}s "
                f"(attempt {attempt + 1}/{max_retries})"
            )
        except requests.exceptions.ConnectionError:
            logger.warning(
                f"Ollama connection refused (attempt {attempt + 1}/{max_retries})"
            )
            # No point retrying if server is down
            return None
        except Exception as exc:
            logger.error(f"Ollama call failed: {exc} (attempt {attempt + 1}/{max_retries})")

        # Wait before retry (except on last attempt)
        if attempt < max_retries - 1:
            time.sleep(_retry_delay)

    logger.error(f"Ollama failed after {max_retries} attempts")
    return None


def resolve_line(
    vendor: str, raw_line: str, db: Session
) -> Optional[NormalizedFinding]:
    """Check learned_mappings for an existing mapping.

    Generates a pattern signature from the raw line and queries the database
    for a prior operator-approved mapping. If found, returns a confirmed finding
    ready for database persistence. No AI involved — this is pure lookup.

    Args:
        vendor: Device vendor (e.g., 'cisco')
        raw_line: The unparsed configuration line
        db: SQLAlchemy session for database queries

    Returns:
        NormalizedFinding if a learned mapping exists, else None.
        The finding carries confidence='confirmed' and mapping_source='learned_mapping'.
    """
    if not raw_line or not raw_line.strip():
        return None

    # Generate pattern signature: replace variable parts with wildcards
    pattern = _generate_pattern_signature(raw_line)

    try:
        mapping = (
            db.query(LearnedMapping)
            .filter(
                LearnedMapping.vendor == vendor,
                LearnedMapping.pattern_signature == pattern,
            )
            .first()
        )

        if mapping:
            logger.info(
                f"Resolved learned mapping for {vendor}: {raw_line[:50]}... -> {mapping.schema_field}"
            )
            return NormalizedFinding(
                schema_field=mapping.schema_field,
                field_value=mapping.examples[0] if mapping.examples else None,
                raw_source_line=raw_line,
                line_number=None,  # Will be set by caller
                confidence=Confidence.CONFIRMED,
                mapping_source=MappingSource.LEARNED_MAPPING,
            )
    except Exception as exc:
        logger.error(f"Error resolving learned mapping: {exc}")

    return None


def classify_with_ollama(
    vendor: str, raw_line: str, schema_reference: dict
) -> Optional[dict[str, Any]]:
    """Use Ollama to propose a schema field mapping for an unknown line.

    Sends the raw line (NO full config data) to Ollama via the standard integration
    pattern: retry logic, JSON format mode, timeout scaling, graceful degradation.

    The AI proposes only; operator approval is required before persistence.

    Args:
        vendor: Device vendor (e.g., 'cisco')
        raw_line: The unparsed configuration line
        schema_reference: Dict mapping schema field names to their descriptions

    Returns:
        Dict with keys:
          - schema_field: str | None (proposed field name from schema, or None if no match)
          - field_value: Any (proposed value for that field)
          - confidence: float (0.0-1.0, Ollama's confidence in the proposal)
        Returns None if Ollama is unreachable or times out.
    """
    if not raw_line or not raw_line.strip():
        return None

    # Build schema reference for the prompt (field names + descriptions)
    schema_desc = "\n".join(
        f"- {field}: {desc}" for field, desc in schema_reference.items()
    )

    prompt = f"""Given a {vendor.upper()} CLI configuration line, propose which schema field it maps to.

Configuration line: {raw_line}

Available schema fields:
{schema_desc}

Return a JSON object with:
- "schema_field": the field name (or null if no match)
- "field_value": the parsed value for that field
- "confidence": your confidence (0.0-1.0)

Example:
{{"schema_field": "ssh_version", "field_value": 2, "confidence": 0.95}}

Response (JSON only):"""

    try:
        response = _call_ollama(
            prompt,
            model="qwen2.5:7b",
            format="json",
            timeout_ms=30000,
            max_retries=3,
        )

        if response is None:
            logger.warning("Ollama unreachable; skipping classification")
            return None

        # Parse the JSON response
        try:
            result = json.loads(response)
            schema_field = result.get("schema_field")
            field_value = result.get("field_value")
            confidence = float(result.get("confidence", 0.5))

            # Validate schema_field is in the reference
            if schema_field and schema_field not in schema_reference:
                logger.warning(
                    f"Ollama proposed unknown schema field: {schema_field}"
                )
                schema_field = None

            logger.info(
                f"Ollama classified {vendor} line: {raw_line[:50]}... -> {schema_field} (confidence={confidence})"
            )

            return {
                "schema_field": schema_field,
                "field_value": field_value,
                "confidence": confidence,
            }
        except json.JSONDecodeError as e:
            logger.error(f"Ollama returned invalid JSON: {response[:100]}... ({e})")
            return None

    except Exception as exc:
        logger.error(f"Error calling Ollama classifier: {exc}")
        return None


def _generate_pattern_signature(raw_line: str) -> str:
    """Generate a regex-like pattern signature for a configuration line.

    Converts specific values to wildcards so similar lines match the same mapping.
    Examples:
      "ip address 192.168.1.1 255.255.255.0" -> "ip address .* .*"
      "username admin password 7 0102030405" -> "username .* password .* .*"

    This pattern is stored in learned_mappings.pattern_signature and used for
    matching during resolve_line().

    Args:
        raw_line: The configuration line to generate a pattern for

    Returns:
        A string pattern with variable parts replaced by wildcards.
    """
    if not raw_line or not raw_line.strip():
        return raw_line or ""

    parts = raw_line.split()
    if not parts:
        return raw_line

    pattern_parts = []
    for part in parts:
        # Keep keywords (lowercase or with hyphens), replace numbers/IPs/hashes
        if part.islower() or (part.replace("-", "").replace("_", "").isalpha() and not part.isdigit()):
            # Looks like a keyword (lowercase, may have hyphens/underscores)
            pattern_parts.append(part)
        else:
            # Looks like a value (IP, number, hash, mixed case, etc.)
            pattern_parts.append(".*")

    return " ".join(pattern_parts)


class DatabaseLearnedMappingResolver:
    """Database-backed implementation of LearnedMappingResolver protocol.

    Used by CiscoIOSNormalizer to check persistent learned mappings during
    parsing. No AI involved — pure database lookup of operator-approved mappings.
    """

    def __init__(self, db: Session):
        self._db = db

    def resolve(self, *, vendor: str, raw_line: str, line_number: int,
                context: str | None) -> MappingMatch | None:
        """Return an approved mapping for a line, or None when unmatched."""
        if not raw_line or not raw_line.strip():
            return None

        pattern = _generate_pattern_signature(raw_line)

        try:
            mapping = (
                self._db.query(LearnedMapping)
                .filter(
                    LearnedMapping.vendor == vendor,
                    LearnedMapping.pattern_signature == pattern,
                )
                .first()
            )

            if mapping:
                logger.info(
                    f"Resolved learned mapping for {vendor}: {raw_line[:50]}... -> {mapping.schema_field}"
                )
                return MappingMatch(
                    schema_field=mapping.schema_field,
                    field_value=mapping.examples[0] if mapping.examples else None,
                )
        except Exception as exc:
            logger.error(f"Error resolving learned mapping: {exc}")

        return None
