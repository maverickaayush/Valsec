"""Tests for Phase 6: Interactive Training Loop

Tests the training module (matcher.py) and training API endpoints, verifying:
- Learned mapping lookup and reuse
- Ollama classifier integration (with mocking)
- Pattern signature generation
"""

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from training.matcher import (
    _generate_pattern_signature,
    classify_with_ollama,
    resolve_line,
)


class TestPatternSignatureGeneration:
    """Test pattern signature generation for learned mapping reuse."""

    def test_basic_pattern_generation(self):
        """Keywords preserved, values replaced with wildcards."""
        line = "ip address 192.168.1.1 255.255.255.0"
        pattern = _generate_pattern_signature(line)
        assert pattern == "ip address .* .*"

    def test_username_password_pattern(self):
        """Username and password keywords preserved."""
        line = "username admin password 7 0102030405"
        pattern = _generate_pattern_signature(line)
        # 'username', 'admin', 'password' are lowercase keywords, '7', '0102030405' are values
        # Note: 'admin' is lowercase so it's treated as a keyword, not a value
        assert pattern == "username admin password .* .*"

    def test_ssh_version_pattern(self):
        """SSH version pattern recognizes keywords."""
        line = "ip ssh version 2"
        pattern = _generate_pattern_signature(line)
        assert pattern == "ip ssh version .*"

    def test_empty_line(self):
        """Empty lines return unchanged."""
        assert _generate_pattern_signature("") == ""
        # Whitespace-only line returns as-is (no transformation needed)
        result = _generate_pattern_signature("   ")
        assert result.strip() == ""  # Should be empty or whitespace-only

    def test_mixed_case_keywords(self):
        """Mixed case values become wildcards."""
        line = "hostname Router-01"
        pattern = _generate_pattern_signature(line)
        # 'hostname' is keyword, 'Router-01' has mixed case so it's a value
        assert pattern == "hostname .*"


class TestResolveLineWithLearnedMappings:
    """Test resolve_line function for learned mapping lookup."""

    def test_resolve_existing_mapping(self):
        """Existing learned mapping is found and returned."""
        mock_db = MagicMock()
        mock_mapping = MagicMock()
        mock_mapping.schema_field = "ssh.version"
        mock_mapping.examples = ["ip ssh version 2"]

        mock_db.query.return_value.filter.return_value.first.return_value = mock_mapping

        finding = resolve_line("cisco", "ip ssh version 2", mock_db)

        assert finding is not None
        assert finding.schema_field == "ssh.version"
        assert finding.raw_source_line == "ip ssh version 2"
        assert finding.confidence == "confirmed"
        assert finding.mapping_source == "learned_mapping"

    def test_resolve_no_matching_mapping(self):
        """Line with no learned mapping returns None."""
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        finding = resolve_line("cisco", "unknown command here", mock_db)
        assert finding is None

    def test_resolve_different_vendor(self):
        """Mapping for different vendor is not matched."""
        mock_db = MagicMock()
        # First call checks for cisco, returns None
        mock_db.query.return_value.filter.return_value.first.return_value = None

        finding = resolve_line("cisco", "set system host-name test", mock_db)
        assert finding is None

    def test_resolve_empty_line(self):
        """Empty lines return None without database query."""
        mock_db = MagicMock()
        assert resolve_line("cisco", "", mock_db) is None
        assert resolve_line("cisco", "   ", mock_db) is None
        # Database should not be queried for empty lines
        mock_db.query.assert_not_called()


class TestOllamaClassifier:
    """Test Ollama-powered classifier (with mocking)."""

    @patch("training.matcher._call_ollama")
    def test_classify_success(self, mock_ollama):
        """Ollama returns valid classification proposal."""
        mock_ollama.return_value = json.dumps({
            "schema_field": "ssh.version",
            "field_value": 2,
            "confidence": 0.95,
        })

        schema_ref = {
            "ssh.version": "SSH protocol version (1 or 2)",
            "device_info.hostname": "Device hostname",
        }

        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is not None
        assert result["schema_field"] == "ssh.version"
        assert result["field_value"] == 2
        assert result["confidence"] == 0.95

    @patch("training.matcher._call_ollama")
    def test_classify_unknown_field(self, mock_ollama):
        """Ollama proposes unknown field, rejected."""
        mock_ollama.return_value = json.dumps({
            "schema_field": "nonexistent_field",
            "field_value": "something",
            "confidence": 0.8,
        })

        schema_ref = {"ssh.version": "SSH protocol version"}

        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        # schema_field set to None because it's not in schema_ref
        assert result is not None
        assert result["schema_field"] is None

    @patch("training.matcher._call_ollama")
    def test_classify_ollama_unreachable(self, mock_ollama):
        """Ollama unreachable, graceful degradation."""
        mock_ollama.return_value = None

        schema_ref = {"ssh.version": "SSH protocol version"}
        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is None

    @patch("training.matcher._call_ollama")
    def test_classify_invalid_json(self, mock_ollama):
        """Ollama returns invalid JSON, handled gracefully."""
        mock_ollama.return_value = "not valid json"

        schema_ref = {"ssh.version": "SSH protocol version"}
        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is None

    @patch("training.matcher._call_ollama")
    def test_classify_empty_line(self, mock_ollama):
        """Empty lines return None without calling Ollama."""
        schema_ref = {"ssh.version": "SSH protocol version"}

        assert classify_with_ollama("cisco", "", schema_ref) is None
        assert classify_with_ollama("cisco", "   ", schema_ref) is None
        mock_ollama.assert_not_called()

    @patch("training.matcher._call_ollama")
    def test_classify_with_valid_field(self, mock_ollama):
        """Ollama proposes valid field, accepted."""
        mock_ollama.return_value = json.dumps({
            "schema_field": "device_info.hostname",
            "field_value": "Router-01",
            "confidence": 0.9,
        })

        schema_ref = {
            "device_info.hostname": "Device hostname",
            "ssh.version": "SSH protocol version",
        }

        result = classify_with_ollama("cisco", "hostname Router-01", schema_ref)

        assert result is not None
        assert result["schema_field"] == "device_info.hostname"
        assert result["field_value"] == "Router-01"
        assert result["confidence"] == 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
