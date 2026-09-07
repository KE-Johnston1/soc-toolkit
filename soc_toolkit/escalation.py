"""Evidence-based escalation decisions for SOC investigations."""

from dataclasses import dataclass
from typing import Literal

EscalationLevel = Literal["No Escalation", "Monitor", "SOC Investigation", "Tier 2", "Incident Response", "Management/Legal/Privacy"]

@dataclass(frozen=True)
class EscalationInput:
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
    level: EscalationLevel
    rationale: str
    triggers: tuple[str, ...]
    evidence_gaps: tuple[str, ...]

def recommend_escalation(case: EscalationInput) -> EscalationDecision:
    """Recommend escalation without declaring an incident by default."""
    triggers: list[str] = []
    gaps: list[str] = []
    if case.privileged_account: triggers.append("privileged account involved")
    if case.multiple_accounts: triggers.append("multiple accounts affected")
    if case.confirmed_malicious_infrastructure: triggers.append("malicious infrastructure evidence established")
    if case.malware_evidence: triggers.append("malware evidence established")
    if case.persistence_evidence: triggers.append("persistence evidence established")
    if case.c2_evidence: triggers.append("command-and-control evidence established")
    if case.exfiltration_evidence: triggers.append("potential exfiltration evidence established")
    if case.sensitive_data_involved: triggers.append("sensitive data may be involved")
    if case.legal_privacy_consideration: triggers.append("legal/privacy review may be relevant")
    if case.containment_risk: triggers.append("safe containment requires specialist review")
    if case.repeated_related_alerts: triggers.append("related alerts are recurring")
    if case.business_impact == "Unknown": gaps.append("business impact is unknown")

    if case.assessment == "Insufficient Evidence":
        return EscalationDecision("Monitor", "The current assessment does not establish enough context for incident escalation; preserve the investigation trail and collect missing evidence.", tuple(triggers), tuple(gaps + ["assessment context remains incomplete"]))
    if case.legal_privacy_consideration or case.sensitive_data_involved:
        return EscalationDecision("Management/Legal/Privacy", "Business, sensitive-data, legal, privacy, or compliance considerations may require stakeholder referral; this is not a legal conclusion.", tuple(triggers), tuple(gaps))
    if case.malware_evidence or case.persistence_evidence or case.c2_evidence or case.exfiltration_evidence:
        return EscalationDecision("Incident Response", "Independent security evidence meets a stronger response threshold; specialist incident-response review is recommended while uncertainty is documented.", tuple(triggers), tuple(gaps))
    if case.privileged_account or case.multiple_accounts or case.confirmed_malicious_infrastructure or case.repeated_related_alerts:
        return EscalationDecision("Tier 2", "Escalation-relevant context warrants deeper security investigation, but the recommendation does not confirm compromise or malicious intent.", tuple(triggers), tuple(gaps))
    if case.assessment == "Expected":
        return EscalationDecision("No Escalation", "The analyst assessment supports expected activity and no separate escalation trigger is established.", tuple(triggers), tuple(gaps))
    return EscalationDecision("SOC Investigation", "The assessment remains unresolved, so continued SOC investigation is recommended rather than automatic incident declaration.", tuple(triggers), tuple(gaps))
