"""Fail-closed fallback for vendors without a hand-written parser.

The adapter never interprets syntax. Every non-empty source line is retained
with its original line number until an operator-approved vendor-scoped learned
mapping resolves it. AI proposals are handled by the existing orchestrator and
remain unverified until the training endpoint receives human approval.
"""
from __future__ import annotations

from typing import Any

from .cisco_ios import LearnedMappingResolver
from .schema import (
    Confidence,
    MappingSource,
    NormalizationResult,
    NormalizedFinding,
    UnknownLine,
)


class GenericFallbackNormalizer:
    """Preserve unsupported-vendor lines without claiming parser recognition."""

    def __init__(self, vendor: str, learned_mapping_resolver: LearnedMappingResolver | None = None):
        self.vendor = vendor
        self._learned_mapping_resolver = learned_mapping_resolver

    def parse(self, raw_config: str) -> NormalizationResult:
        result = NormalizationResult()
        for line_number, raw_line in enumerate(raw_config.splitlines(), 1):
            if not raw_line.strip():
                continue
            match = None
            if self._learned_mapping_resolver is not None:
                match = self._learned_mapping_resolver.resolve(
                    vendor=self.vendor,
                    raw_line=raw_line,
                    line_number=line_number,
                    context=None,
                )
            if match is not None and self._assign(result, match.schema_field, match.field_value):
                result.findings.append(NormalizedFinding(
                    schema_field=match.schema_field,
                    field_value=match.field_value,
                    raw_source_line=raw_line,
                    line_number=line_number,
                    confidence=Confidence.CONFIRMED,
                    mapping_source=MappingSource.LEARNED_MAPPING,
                ))
            else:
                result.unknown_lines.append(UnknownLine(raw_line, line_number))
        return result

    @staticmethod
    def _assign(result: NormalizationResult, field: str, value: Any) -> bool:
        """Apply only a real neutral-schema field; preserve the line otherwise."""
        parts = field.split(".")
        if len(parts) != 2:
            return False
        target = getattr(result.config, parts[0], None)
        if target is None or not hasattr(target, parts[1]):
            return False
        current = getattr(target, parts[1])
        if isinstance(current, list):
            for item in value if isinstance(value, list) else [value]:
                if item not in current:
                    current.append(item)
        else:
            setattr(target, parts[1], value)
        return True
