"""Evidence-aware organisational risk context for SOC investigations."""

from dataclasses import dataclass
from typing import Literal

Impact = Literal["Unknown", "Low", "Medium", "High"]
Confidence = Literal["Low", "Medium", "High"]
ValueBasis = Literal["Unknown", "Observed", "Derived", "Estimated"]


@dataclass(frozen=True)
class RiskInput:
    """Context used to describe risk without treating it as proof of compromise."""

    asset_criticality: Impact = "Unknown"
    account_privilege: Impact = "Unknown"
    data_sensitivity: Impact = "Unknown"
    likelihood: Impact = "Unknown"
    business_impact: Impact = "Unknown"
    financial_impact: Impact = "Unknown"
    financial_basis: ValueBasis = "Unknown"
    legal_regulatory_consideration: bool = False
    cve_relevance: str = "Unknown"
    cvss_severity: str = "Unknown"
    confidence: Confidence = "Low"


@dataclass(frozen=True)
class RiskAssessment:
    """Structured risk context and analyst rationale."""

    overall_risk: Impact
    confidence: Confidence
    rationale: str
    evidence_gaps: tuple[str, ...]
    financial_basis: ValueBasis
    legal_regulatory_consideration: bool
    cve_relevance: str
    cvss_severity: str


def assess_risk(case: RiskInput) -> RiskAssessment:
    """Assess organisational risk context while preserving uncertainty.

    Risk is not a compromise verdict. CVSS describes vulnerability severity;
    organisational risk also depends on exposure, asset importance, evidence,
    likelihood, and impact.
    """
    gaps: list[str] = []
    for name, value in (
        ("asset criticality", case.asset_criticality),
        ("account privilege", case.account_privilege),
        ("data sensitivity", case.data_sensitivity),
        ("likelihood", case.likelihood),
        ("business impact", case.business_impact),
        ("financial impact", case.financial_impact),
    ):
        if value == "Unknown":
            gaps.append(f"{name} is unknown")

    if case.financial_impact != "Unknown" and case.financial_basis == "Unknown":
        gaps.append("financial impact is stated without a documented value basis")

    known_high = sum(
        value == "High"
        for value in (
            case.asset_criticality,
            case.account_privilege,
            case.data_sensitivity,
            case.likelihood,
            case.business_impact,
        )
    )

    if known_high >= 3:
        overall = "High"
    elif known_high >= 1:
        overall = "Medium"
    elif gaps:
        overall = "Unknown"
    else:
        overall = "Low"

    if gaps:
        rationale = (
            "Risk context is provisional because one or more impact, likelihood, "
            "or financial inputs remain unknown. Risk does not establish compromise."
        )
    else:
        rationale = (
            "Risk is derived from the supplied organisational context; it is not "
            "a statement that the underlying security event is confirmed."
        )

    return RiskAssessment(
        overall_risk=overall,
        confidence=case.confidence,
        rationale=rationale,
        evidence_gaps=tuple(gaps),
        financial_basis=case.financial_basis,
        legal_regulatory_consideration=case.legal_regulatory_consideration,
        cve_relevance=case.cve_relevance,
        cvss_severity=case.cvss_severity,
    )
