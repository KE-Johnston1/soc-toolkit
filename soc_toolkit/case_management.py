"""Controlled SOC case lifecycle and decision trail."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

CaseStatus = Literal[
    "Open", "Investigating", "Escalated", "Contained", "Remediation", "Recovery", "Closed"
]

_ALLOWED: dict[CaseStatus, tuple[CaseStatus, ...]] = {
    "Open": ("Investigating", "Escalated", "Closed"),
    "Investigating": ("Escalated", "Contained", "Remediation", "Recovery", "Closed"),
    "Escalated": ("Investigating", "Contained", "Remediation", "Recovery", "Closed"),
    "Contained": ("Investigating", "Remediation", "Recovery", "Closed"),
    "Remediation": ("Investigating", "Recovery", "Closed"),
    "Recovery": ("Investigating", "Closed"),
    "Closed": (),
}


@dataclass(frozen=True)
class CaseEvent:
    timestamp: datetime
    stage: str
    action: str
    actor_role: str
    observation: str
    rationale: str
    confidence: str
    evidence_source: str

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("case event timestamp must be timezone-aware")
        for name in ("stage", "action", "actor_role", "observation", "rationale", "evidence_source"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be blank")


@dataclass
class CaseRecord:
    case_id: str
    alert_id: str
    created_at: datetime
    status: CaseStatus = "Open"
    owner: str = ""
    assessment: str = "Insufficient Evidence"
    risk: str = "Unknown"
    escalation: str = "Monitor"
    response: str = "Investigate"
    evidence_gaps: list[str] = field(default_factory=list)
    decision_trail: list[CaseEvent] = field(default_factory=list)
    closure_rationale: str = ""

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise ValueError("case created_at must be timezone-aware")
        if not self.case_id.strip() or not self.alert_id.strip():
            raise ValueError("case_id and alert_id cannot be blank")


def transition_case(
    case: CaseRecord,
    new_status: CaseStatus,
    *,
    actor_role: str,
    rationale: str,
    evidence_source: str = "case record",
    confidence: str = "Medium",
    timestamp: datetime | None = None,
) -> CaseRecord:
    """Apply one validated lifecycle transition and record its decision trail."""
    if new_status not in _ALLOWED[case.status]:
        raise ValueError(f"invalid case transition: {case.status} -> {new_status}")
    if not rationale.strip():
        raise ValueError("transition rationale cannot be blank")
    if not actor_role.strip():
        raise ValueError("actor_role cannot be blank")
    if new_status == "Closed":
        if case.assessment != "Expected":
            raise ValueError("case cannot close unless assessment is Expected")
        if case.evidence_gaps:
            raise ValueError("case cannot close while evidence gaps remain")
        if not case.closure_rationale.strip():
            raise ValueError("case closure requires a documented rationale")
    when = timestamp or datetime.now(timezone.utc)
    case.status = new_status
    case.decision_trail.append(
        CaseEvent(
            timestamp=when,
            stage="case management",
            action=f"status transition to {new_status}",
            actor_role=actor_role,
            observation=f"Case {case.case_id} moved from the prior lifecycle state to {new_status}.",
            rationale=rationale,
            confidence=confidence,
            evidence_source=evidence_source,
        )
    )
    return case
