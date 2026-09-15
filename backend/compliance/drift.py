"""Pure, deterministic control and raw-configuration drift reporting."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import difflib
from typing import Any, Iterable, Sequence


@dataclass(frozen=True)
class ControlDelta:
    control_id: str
    title: str
    severity: str
    previous_verdict: str | None
    current_verdict: str
    changed: bool


@dataclass(frozen=True)
class DriftReport:
    baseline_config_id: str | None
    compare_config_id: str
    score_before: float | None
    score_after: float
    newly_failed: list[ControlDelta]
    newly_passed: list[ControlDelta]
    still_failing: list[ControlDelta]
    unchanged_count: int
    raw_config_diff: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _value(record: Any, name: str) -> Any:
    value = record.get(name) if isinstance(record, dict) else getattr(record, name)
    return value.value if hasattr(value, "value") else value


def _score(records: Iterable[Any]) -> float:
    verdicts = [_value(record, "verdict") for record in records]
    passed = sum(verdict == "PASS" for verdict in verdicts)
    failed = sum(verdict == "FAIL" for verdict in verdicts)
    return round((passed / (passed + failed)) * 100, 2) if passed + failed else 0.0


def build_drift_report(
    baseline_results: Sequence[Any] | None,
    current_results: Sequence[Any],
    baseline_raw_config: str,
    current_raw_config: str,
    *,
    baseline_config_id: str | None,
    compare_config_id: str,
) -> DriftReport:
    """Compare ordered persisted results without DB, network, or AI access."""
    previous = {
        (_value(record, "framework"), _value(record, "control_id")): record
        for record in (baseline_results or ())
    }
    newly_failed: list[ControlDelta] = []
    newly_passed: list[ControlDelta] = []
    still_failing: list[ControlDelta] = []
    unchanged_count = 0
    for record in current_results:
        key = (_value(record, "framework"), _value(record, "control_id"))
        prior = previous.get(key)
        previous_verdict = _value(prior, "verdict") if prior is not None else None
        current_verdict = _value(record, "verdict")
        delta = ControlDelta(
            control_id=str(_value(record, "control_id")),
            title=str(_value(record, "title")),
            severity=str(_value(record, "severity")),
            previous_verdict=previous_verdict,
            current_verdict=current_verdict,
            changed=previous_verdict != current_verdict,
        )
        if current_verdict == "FAIL" and previous_verdict != "FAIL":
            newly_failed.append(delta)
        elif current_verdict == "PASS" and previous_verdict == "FAIL":
            newly_passed.append(delta)
        elif current_verdict == "FAIL" and previous_verdict == "FAIL":
            still_failing.append(delta)
        if previous_verdict == current_verdict:
            unchanged_count += 1

    raw_diff = "\n".join(difflib.unified_diff(
        baseline_raw_config.splitlines(),
        current_raw_config.splitlines(),
        fromfile="before", tofile="after", lineterm="",
    ))
    return DriftReport(
        baseline_config_id=baseline_config_id,
        compare_config_id=compare_config_id,
        score_before=_score(baseline_results) if baseline_results is not None else None,
        score_after=_score(current_results),
        newly_failed=newly_failed,
        newly_passed=newly_passed,
        still_failing=still_failing,
        unchanged_count=unchanged_count,
        raw_config_diff=raw_diff,
    )
