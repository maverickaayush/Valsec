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
    DatabaseLearnedMappingResolver,
    _generate_pattern_signature,
    classify_with_ollama,
    resolve_line,
)
from analysis.ollama_client import propose_config_mappings, propose_config_remediation
from config import settings


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

    def test_mapping_reuse_is_scoped_to_approving_user(self):
        user_a, user_b = uuid4(), uuid4()
        mapping = MagicMock(
            user_id=user_a,
            schema_field="ssh.version",
            examples=[{"raw_line": "vendor ssh generation 2", "field_value": 2}],
        )

        class ScopeQuery:
            def __init__(self): self.requested_user = None
            def filter(self, *criteria):
                for criterion in criteria:
                    if getattr(getattr(criterion, "left", None), "key", None) == "user_id":
                        self.requested_user = getattr(getattr(criterion, "right", None), "value", None)
                return self
            def first(self): return mapping if self.requested_user == mapping.user_id else None

        db = MagicMock()
        db.query.side_effect = lambda *_: ScopeQuery()
        line = "vendor ssh generation 2"
        assert DatabaseLearnedMappingResolver(db, user_a).resolve(
            vendor="cisco", raw_line=line, line_number=1, context=None
        ) is not None
        assert DatabaseLearnedMappingResolver(db, user_b).resolve(
            vendor="cisco", raw_line=line, line_number=1, context=None
        ) is None
        assert DatabaseLearnedMappingResolver(db, user_a).resolve(
            vendor="cisco", raw_line=line, line_number=1, context=None
        ) is not None


class TestOllamaClassifier:
    """Test Ollama-powered classifier (with mocking)."""

    @patch("training.matcher.propose_config_mappings")
    def test_classify_success(self, mock_ollama):
        """Ollama returns valid classification proposal."""
        mock_ollama.return_value = {1: {
            "schema_field": "ssh.version",
            "field_value": 2,
            "confidence": 0.95,
        }}

        schema_ref = {
            "ssh.version": "SSH protocol version (1 or 2)",
            "device_info.hostname": "Device hostname",
        }

        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is not None
        assert result["schema_field"] == "ssh.version"
        assert result["field_value"] == 2
        assert result["confidence"] == 0.95

    @patch("training.matcher.propose_config_mappings")
    def test_classify_unknown_field(self, mock_ollama):
        """The shared client rejects unknown fields."""
        mock_ollama.return_value = {}

        schema_ref = {"ssh.version": "SSH protocol version"}

        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is None

    @patch("training.matcher.propose_config_mappings")
    def test_classify_ollama_unreachable(self, mock_ollama):
        """Ollama unreachable, graceful degradation."""
        mock_ollama.return_value = {}

        schema_ref = {"ssh.version": "SSH protocol version"}
        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is None

    @patch("training.matcher.propose_config_mappings")
    def test_classify_invalid_json(self, mock_ollama):
        """Invalid Ollama output is discarded by the shared client."""
        mock_ollama.return_value = {}

        schema_ref = {"ssh.version": "SSH protocol version"}
        result = classify_with_ollama("cisco", "ip ssh version 2", schema_ref)

        assert result is None

    @patch("training.matcher.propose_config_mappings")
    def test_classify_empty_line(self, mock_ollama):
        """Empty lines return None without calling Ollama."""
        schema_ref = {"ssh.version": "SSH protocol version"}

        assert classify_with_ollama("cisco", "", schema_ref) is None
        assert classify_with_ollama("cisco", "   ", schema_ref) is None
        mock_ollama.assert_not_called()

    @patch("training.matcher.propose_config_mappings")
    def test_classify_with_valid_field(self, mock_ollama):
        """Ollama proposes valid field, accepted."""
        mock_ollama.return_value = {1: {
            "schema_field": "device_info.hostname",
            "field_value": "Router-01",
            "confidence": 0.9,
        }}

        schema_ref = {
            "device_info.hostname": "Device hostname",
            "ssh.version": "SSH protocol version",
        }

        result = classify_with_ollama("cisco", "hostname Router-01", schema_ref)

        assert result is not None
        assert result["schema_field"] == "device_info.hostname"
        assert result["field_value"] == "Router-01"
        assert result["confidence"] == 0.9


class TestSharedOllamaConfigClient:
    def test_batches_and_validates_proposals(self, monkeypatch):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {"content": json.dumps({"proposals": [
                {"line_number": 4, "schema_field": "ssh.version", "field_value": 2, "confidence": 0.88},
                {"line_number": 5, "schema_field": "not.real", "field_value": True, "confidence": 0.99},
            ]})}
        }
        post = MagicMock(return_value=response)
        monkeypatch.setattr("analysis.ollama_client.requests.post", post)
        monkeypatch.setattr(settings, "OLLAMA_URL", "http://127.0.0.1:11434")
        result = propose_config_mappings(
            "cisco",
            [
                {"line_number": 4, "raw_source_line": "vendor ssh generation 2", "context": None},
                {"line_number": 5, "raw_source_line": "future command", "context": None},
            ],
            {"ssh.version": "SSH version"},
        )
        assert result == {4: {"schema_field": "ssh.version", "field_value": 2, "confidence": 0.88}}
        assert post.call_count == 1
        sent = post.call_args.kwargs["json"]
        assert len(json.loads(sent["messages"][1]["content"])["unknown_lines"]) == 2

    def test_refuses_non_local_ollama_endpoint(self, monkeypatch):
        post = MagicMock()
        monkeypatch.setattr("analysis.ollama_client.requests.post", post)
        monkeypatch.setattr(settings, "OLLAMA_URL", "https://models.example.com")
        result = propose_config_mappings(
            "cisco",
            [{"line_number": 1, "raw_source_line": "future command"}],
            {"ssh.version": "SSH version"},
        )
        assert result == {}
        post.assert_not_called()

    def test_structured_remediation_accepts_safe_cli_and_rejects_destructive_cli(self, monkeypatch):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {"content": json.dumps({"cli_commands": [
                "configure terminal", "no service legacy", "end"
            ]})}
        }
        monkeypatch.setattr("analysis.ollama_client.requests.post", MagicMock(return_value=response))
        monkeypatch.setattr(settings, "OLLAMA_URL", "http://localhost:11434")
        kwargs = dict(
            vendor="cisco", os_type="ios", framework="NIST SP 800-53 Rev. 5",
            control_id="CM-7", title="Least Functionality", observed_detail="Legacy service enabled",
        )
        assert propose_config_remediation(**kwargs) == "configure terminal\nno service legacy\nend"

        response.json.return_value = {
            "message": {"content": json.dumps({"cli_commands": ["write erase", "reload"]})}
        }
        monkeypatch.setattr("analysis.ollama_client.time.sleep", lambda *_: None)
        assert propose_config_remediation(**kwargs) is None

        response.json.return_value = {
            "message": {"content": json.dumps({"cli_commands": [
                "configure terminal", "do show running-config", "end"
            ]})}
        }
        assert propose_config_remediation(**kwargs) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
