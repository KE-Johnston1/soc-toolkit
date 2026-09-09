"""Scenario context for evidence-led SOC investigations."""

from dataclasses import dataclass
from typing import Literal

ScenarioType = Literal[
    "Unknown",
    "Credential Attack",
    "Malware",
    "Command and Control",
    "Exfiltration",
    "Phishing",
    "Impersonation",
    "Social Engineering",
    "Insider Threat",
    "AI-Assisted Attack",
]


_REQUIRED: dict[ScenarioType, tuple[str, ...]] = {
    "Credential Attack": ("authentication evidence", "account context", "source context"),
    "Malware": ("endpoint evidence", "process/file evidence", "network context"),
    "Command and Control": ("network evidence", "destination context", "endpoint/process correlation"),
    "Exfiltration": ("source and destination evidence", "transfer volume or scope", "data classification and authorization"),
    "Phishing": ("message or delivery evidence", "recipient/account context", "link/file or authentication outcome"),
    "Impersonation": ("identity claim", "identity verification evidence", "authentication and authorization context"),
    "Social Engineering": ("interaction evidence", "claimed identity or pretext", "resulting action or access"),
    "Insider Threat": ("account and ownership context", "expected activity baseline", "independent evidence of intent or policy violation"),
    "AI-Assisted Attack": ("attack indicator", "supporting identity/content or telemetry evidence", "independent corroboration"),
    "Unknown": (),
}


@dataclass(frozen=True)
class ScenarioContext:
    """A possible investigation scenario, kept separate from incident confirmation."""

    scenario_type: ScenarioType = "Unknown"
    indicator_present: bool = False
    classification_established: bool = False
    confidence: Literal["Unknown", "Low", "Medium", "High"] = "Unknown"
    evidence_gaps: tuple[str, ...] = ()
    rationale: str = "No scenario classification has been established."

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            raise ValueError("scenario rationale cannot be blank")
        if self.classification_established and not self.indicator_present:
            raise ValueError("an established scenario requires an indicator")


def required_evidence(context: ScenarioContext) -> tuple[str, ...]:
    """Return evidence categories needed to test the selected scenario."""
    return _REQUIRED[context.scenario_type]


def scenario_gaps(context: ScenarioContext, available: set[str]) -> tuple[str, ...]:
    """Identify missing evidence categories without asserting the scenario."""
    return tuple(item for item in required_evidence(context) if item not in available)
