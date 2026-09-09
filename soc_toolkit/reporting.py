"""Structured analyst reporting for reproducible synthetic SOC cases."""

from dataclasses import dataclass
from typing import Literal

Assessment = Literal["Expected", "Requires Investigation", "Insufficient Evidence", "Security Concern"]
EvidenceType = Literal["observed", "correlated", "inferred", "hypothesis", "unknown"]

@dataclass(frozen=True)
class ReportEvidence:
    evidence_id: str
    source: str
    observation: str
    evidence_type: EvidenceType
    confidence: str
    relationship: Literal["supports", "challenges", "neutral"] = "neutral"

    def __post_init__(self) -> None:
        for name in ("evidence_id", "source", "observation", "confidence"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be blank")

@dataclass(frozen=True)
class AnalystReport:
    case_id: str
    title: str
    scenario: str
    assessment: Assessment
    confidence: str
    executive_summary: str
    key_observations: tuple[str, ...]
    evidence: tuple[ReportEvidence, ...]
    hypotheses: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    risk_summary: str
    escalation_summary: str
    response_summary: str
    closure_status: str
    lessons_learned: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("case_id", "title", "scenario", "confidence", "executive_summary", "risk_summary", "escalation_summary", "response_summary", "closure_status"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be blank")
        if not self.key_observations:
            raise ValueError("key_observations cannot be empty")

def render_markdown(report: AnalystReport) -> str:
    lines = [f"# {report.title}", "", f"- **Case:** `{report.case_id}`", f"- **Scenario:** {report.scenario}", f"- **Assessment:** {report.assessment}", f"- **Confidence:** {report.confidence}", "", "## Executive summary", "", report.executive_summary, "", "## Key observations", ""]
    lines.extend(f"- {item}" for item in report.key_observations)
    lines.extend(["", "## Evidence matrix", "", "| ID | Source | Type | Confidence | Relationship | Observation |", "|---|---|---|---|---|---|"])
    for item in report.evidence:
        observation = item.observation.replace("|", "\\|")
        lines.append(f"| {item.evidence_id} | {item.source} | {item.evidence_type} | {item.confidence} | {item.relationship} | {observation} |")
    lines.extend(["", "## Competing hypotheses", ""])
    lines.extend(f"- {item}" for item in report.hypotheses)
    lines.extend(["", "## Evidence gaps", ""])
    lines.extend((f"- {item}" for item in report.evidence_gaps)) if report.evidence_gaps else lines.append("- None recorded")
    lines.extend(["", "## Risk", "", report.risk_summary, "", "## Escalation", "", report.escalation_summary, "", "## Response", "", report.response_summary, "", "## Closure", "", report.closure_status, "", "## Lessons learned", ""])
    lines.extend(f"- {item}" for item in report.lessons_learned)
    lines.extend(["", "> This report uses synthetic evidence. It does not establish compromise, attribution, legal breach, or financial loss unless independently verified.", ""])
    return "\n".join(lines)
