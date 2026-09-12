"""Pure deterministic evaluator for modular compliance control catalogues.

This module intentionally imports no AI, network, database, or task component.
The same normalized schema always produces the same ordered results and score.
"""
from dataclasses import dataclass
from enum import StrEnum

from normalizer.schema import VendorNeutralConfig

from .catalogues import get_controls


class ComplianceVerdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ComplianceResult:
    control_id: str
    title: str
    framework: str
    severity: str
    verdict: ComplianceVerdict
    observed_detail: str
    remediation_reference: str


@dataclass(frozen=True)
class ComplianceReport:
    results: tuple[ComplianceResult, ...]
    compliance_score: float
    total_passed: int
    total_failed: int
    total_na: int


def calculate_compliance_score(results: tuple[ComplianceResult, ...]) -> float:
    """Return PASS percentage across applicable controls, rounded to 2 decimals.

    N/A controls are excluded because no auditable evidence makes them applicable.
    A report with no applicable controls is deterministically scored as 0.0.
    """
    applicable = [result for result in results if result.verdict != ComplianceVerdict.NOT_APPLICABLE]
    if not applicable:
        return 0.0
    passed = sum(result.verdict == ComplianceVerdict.PASS for result in applicable)
    return round((passed / len(applicable)) * 100, 2)


def evaluate_compliance(
    config: VendorNeutralConfig,
    framework_key: str = "cis_cisco_ios_v1",
    vendor: str = "cisco",
) -> ComplianceReport:
    """Evaluate one registered catalogue without side effects or AI input."""
    controls = get_controls(framework_key, vendor)
    results = tuple(
        ComplianceResult(
            control_id=control.control_id,
            title=control.title,
            framework=control.framework,
            severity=control.severity,
            verdict=ComplianceVerdict(verdict),
            observed_detail=detail,
            remediation_reference=control.remediation_reference,
        )
        for control in controls
        for verdict, detail in (control.evaluate(config),)
    )
    return ComplianceReport(
        results=results,
        compliance_score=calculate_compliance_score(results),
        total_passed=sum(result.verdict == ComplianceVerdict.PASS for result in results),
        total_failed=sum(result.verdict == ComplianceVerdict.FAIL for result in results),
        total_na=sum(result.verdict == ComplianceVerdict.NOT_APPLICABLE for result in results),
    )


def evaluate_cis_cisco_ios(config: VendorNeutralConfig) -> ComplianceReport:
    """Backward-compatible Cisco CIS evaluator."""
    return evaluate_compliance(config, "cis_cisco_ios_v1", "cisco")
