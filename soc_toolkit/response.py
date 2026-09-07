"""Evidence-aware response decisions for SOC investigations."""

from dataclasses import dataclass
from typing import Literal

ResponseAction = Literal[
    "Monitor", "Investigate", "Escalate", "Contain", "Remediate", "Recover", "Close"
]


@dataclass(frozen=True)
class ResponseInput:
    """Facts used to recommend the next response action."""

    assessment: str
    confidence: str
    escalation_level: str = "No Escalation"
    evidence_gaps: tuple[str, ...] = ()
    containment_authorized: bool = False
    containment_safe: bool = False
    remediation_authorized: bool = False
    recovery_ready: bool = False
    closure_criteria_met: bool = False
    closure_rationale: str = ""


@dataclass(frozen=True)
class ResponseDecision:
    action: ResponseAction
    rationale: str
    evidence_requirements: tuple[str, ...]
    authorization_required: bool


def recommend_response(case: ResponseInput) -> ResponseDecision:
    """Recommend a controlled response without treating detection as compromise."""
    if case.closure_criteria_met:
        if case.assessment != "Expected" or case.evidence_gaps or not case.closure_rationale.strip():
            return ResponseDecision(
                "Investigate",
                "Closure criteria cannot be accepted because the assessment, evidence gaps, or closure rationale remain incomplete.",
                ("resolve the assessment and all critical evidence gaps", "document a closure rationale"),
                False,
            )
        return ResponseDecision("Close", "Closure criteria are met and a documented rationale is present.", (), False)

    if case.escalation_level == "Incident Response":
        if case.containment_authorized and case.containment_safe:
            return ResponseDecision("Contain", "Incident-response escalation and safe, authorized containment conditions are established.", ("preserve relevant evidence before disruptive action where applicable",), False)
        return ResponseDecision("Escalate", "Incident-response review is recommended; containment is not selected without explicit authorization and a safe containment condition.", ("confirm containment authority and safety",), True)

    if case.assessment == "Insufficient Evidence":
        return ResponseDecision("Investigate", "The available context is insufficient for closure or disruptive response.", case.evidence_gaps or ("collect the missing contextual evidence",), False)

    if case.assessment == "Requires Investigation" or case.escalation_level in {"Tier 2", "SOC Investigation"}:
        return ResponseDecision("Escalate" if case.escalation_level in {"Tier 2", "SOC Investigation"} else "Investigate", "The case remains unresolved, so continued investigation or the recommended specialist escalation is safer than automatic containment.", case.evidence_gaps, False)

    if case.assessment == "Security Concern":
        if case.containment_authorized and case.containment_safe:
            return ResponseDecision("Contain", "A security concern is established and containment is explicitly authorized and assessed as safe.", ("preserve evidence and follow the applicable containment playbook",), False)
        return ResponseDecision("Escalate", "A security concern warrants specialist review; containment is not recommended without explicit authorization and safety validation.", ("confirm containment authority and safe procedure",), True)

    if case.recovery_ready:
        return ResponseDecision("Recover", "Recovery conditions are documented and the case is ready for controlled recovery.", (), False)
    if case.remediation_authorized:
        return ResponseDecision("Remediate", "Remediation is authorized and appropriate for the current evidence state.", (), False)
    return ResponseDecision("Monitor", "No disruptive response condition is established; continue controlled monitoring and document the case.", (), False)
