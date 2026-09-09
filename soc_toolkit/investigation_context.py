"""Structured investigation context for risk, vulnerability, impact, and attribution."""

from dataclasses import dataclass
from typing import Literal
import re

Level = Literal["Unknown", "Low", "Medium", "High"]
ValueBasis = Literal["Unknown", "Observed", "Derived", "Estimated"]
AttributionConfidence = Literal["Unknown", "Low", "Medium", "High"]

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class VulnerabilityContext:
    """CVE/CVSS context without asserting that a vulnerability was exploited."""

    product: str = "Unknown"
    version: str = "Unknown"
    version_confirmed: bool = False
    cve_id: str = "Unknown"
    vulnerability_applicable: bool | None = None
    exploitation_evidence: bool = False
    cvss_severity: str = "Unknown"

    def __post_init__(self) -> None:
        if self.cve_id != "Unknown" and not _CVE_PATTERN.fullmatch(self.cve_id):
            raise ValueError("cve_id must use a CVE identifier or Unknown")
        if self.exploitation_evidence and self.vulnerability_applicable is not True:
            raise ValueError("exploitation evidence requires an applicable vulnerability")


@dataclass(frozen=True)
class ImpactContext:
    """Business and financial impact with an explicit evidence basis."""

    operational_impact: Level = "Unknown"
    business_impact: Level = "Unknown"
    financial_impact: Level = "Unknown"
    financial_value: float | None = None
    financial_basis: ValueBasis = "Unknown"
    data_sensitivity: Level = "Unknown"

    def __post_init__(self) -> None:
        if self.financial_value is not None and self.financial_value < 0:
            raise ValueError("financial_value cannot be negative")
        if self.financial_value is not None and self.financial_basis == "Unknown":
            raise ValueError("financial_value requires an explicit value basis")


@dataclass(frozen=True)
class LegalPrivacyContext:
    """Workflow referral context; this is not legal or breach advice."""

    consideration_present: bool = False
    data_category: str = "Unknown"
    jurisdiction: str = "Unknown"
    evidence_established: bool = False
    referral_required: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.referral_required and not self.consideration_present:
            raise ValueError("legal/privacy referral requires a stated consideration")


@dataclass(frozen=True)
class AttributionContext:
    """Attribution context that explicitly preserves proxy/NAT uncertainty."""

    source_ip: str = "Unknown"
    source_identity: str = "Unknown"
    identity_verified: bool = False
    shared_or_proxied_source_possible: bool = False
    confidence: AttributionConfidence = "Unknown"
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            raise ValueError("attribution rationale cannot be blank")


@dataclass(frozen=True)
class InvestigationContext:
    vulnerability: VulnerabilityContext = VulnerabilityContext()
    impact: ImpactContext = ImpactContext()
    legal_privacy: LegalPrivacyContext = LegalPrivacyContext()
    attribution: AttributionContext = AttributionContext(rationale="Attribution has not been established from the available evidence.")


def assess_vulnerability(context: VulnerabilityContext) -> tuple[str, tuple[str, ...]]:
    """Classify vulnerability relevance separately from exploitation."""
    gaps: list[str] = []
    if context.product == "Unknown":
        gaps.append("affected product is unknown")
    if context.version == "Unknown" or not context.version_confirmed:
        gaps.append("affected version is not confirmed")
    if context.cve_id == "Unknown":
        gaps.append("CVE identifier is unknown")
    if context.vulnerability_applicable is None:
        gaps.append("CVE applicability is unknown")
    if context.vulnerability_applicable is False:
        return "Not Applicable", tuple(gaps)
    if context.exploitation_evidence:
        return "Potentially Exploited - Validate", tuple(gaps)
    if context.vulnerability_applicable is True:
        return "Potentially Relevant - Exploitation Not Established", tuple(gaps)
    return "Unknown", tuple(gaps)
