"""Training module: operator-approved mapping persistence and Ollama classification.

This module handles the interactive training loop that allows operators to classify
unknown configuration lines. Approved mappings persist to the learned_mappings table
and are reused on subsequent audits, all while maintaining the deterministic/AI split:
AI proposes classifications only; compliance verdicts remain 100% deterministic.
"""

from .matcher import resolve_line, classify_with_ollama

__all__ = ["resolve_line", "classify_with_ollama"]
