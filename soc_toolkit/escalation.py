"""Evidence-based escalation decisions for SOC investigations."""

from dataclasses import dataclass
from typing import Literal

EscalationLevel = Literal[
    "No Escalation",
    "Monitor",
    "SOC Investigation",
    "Tier 2",
    "Incident Response",
    "Management/Legal/Privacy",
]


@dataclass(frozen=True)
class EscalationInput:
    """Facts used to recommend escalation; severity alone is insufficient."""

    assessment: str
    confidence: str
    privileged_account: bool = False
    multiple_accounts: bool = False
    confirmed_malicious_infrastructure: bool = False
    malware_evidence: bool = False
    persistence_evidence: bool = False
    c2_evidence: bool = False
    exfiltration_evidence: bool = False
    business_impact: str = "Unknown"
    sensitive_data_involved: bool = False
    legal_privacy_consideration: bool = False
    containment_risk: bool = False
    repeated_related_alerts: bool = False


@dataclass(frozen=True)
class EscalationDecision:
    """Recommended escalation destination with explicit supporting reasons."""

    level: EscalationLevel
    rationale: str
    triggers: tuple[str, ...]
    evidence_gaps: tuple[str, ...]


def recommend_escalation(case: EscalationInput) -> EscalationDecision:
    """Recommend an escalation level without declaring an incident by default."""
    triggers: list[str] = []
    gaps: list[str] = []

    if case.privileged_account:
        triggers.append("privileged account involved")
    if case.multiple_accounts:
        triggers.append("multiple accounts affected")
    if case.confirmed_malicious_infrastructure:
        triggers.append("malicious infrastructure evidence established")
    if case.malware_evidence:
        triggers.append("malware evidence established")
    if case.persistence_evidence:
        triggers.append("persistence evidence established")
    if case.c2_evidence:
        triggers.append("command-and-control evidence established")
    if case.exfiltration_evidence:
        triggers.append("potential exfiltration evidence established")
    if case.sensitive_data_involved:
        triggers.append("sensitive data may be involved")
    if case.legal_privacy_consideration:
        triggers.append("legal/privacy review may be relevant")
    if case.containment_risk:
        triggers.append("safe containment requires specialist review")
    if case.repeated_related_alerts:
        triggers.append("related alerts are recurring")

    if case.business_impact == "Unknown":
        gaps.append("business impact is unknown")

    if case.assessment == "Insufficient Evidence":
        return EscalationDecision(
            level="Monitor",
            rationale="The current assessment does not establish enough context for incident escalation; preserve the investigation trail and collect missing evidence.",
            triggers=tuple(triggers),
            evidence_gaps=tuple(gaps + ["assessment context remains incomplete"]),
        )

    if case.legal_privacy_consideration or case.sensitive_data_involved:
        return EscalationDecision(
            level="Management/Legal/Privacy",
            rationale="The available context indicates that management, legal, privacy, or compliance stakeholders may need to assess implications; this is a referral recommendation, not a legal conclusion.",
            triggers=tuple(triggers),
            evidence_gaps=tuple(gaps),
        )

    if case.malware_evidence or case.persistence_evidence or case.c2_evidence or case.exfiltration_evidence:
        return EscalationDecision(
            level="Incident Response",
            rationale="Independent security evidence meets a stronger response threshold; specialist incident-response review is recommended while remaining uncertainty is documented.",
            triggers=tuple(triggers),
            evidence_gaps=tuple(gaps),
        )

    if case.privileged_account or case.multiple_accounts or case.confirmed_malicious_infrastructure or case.repeated_related_alerts:
        return EscalationDecision(
            level="Tier 2",
            rationale="The case contains escalation-relevant context that warrants deeper security investigation, but the escalation recommendation does not itself confirm compromise or malicious intent.",
            triggers=tuple(triggers),
            evidence_gaps=tuple(gaps),
        )

    if case.assessment == "Expected":
        return EscalationDecision(
            level="No Escalation",
            rationale="The analyst assessment supports expected activity and no separate escalation trigger is established.",
            triggers=tuple(triggers),
            evidence_gaps=tuple(gaps),
        )

    return EscalationDecision(
        level="SOC Investigation",
        rationale="The assessment remains unresolved, so continued SOC investigation is recommended rather than automatic incident declaration.",
        triggers=tuple(triggers),
        evidence_gaps=tuple(gaps),
    )
