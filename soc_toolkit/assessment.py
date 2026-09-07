"""Evidence-first analyst assessment for SOC Toolkit detections.

Detection identifies a signal. This layer evaluates whether the available
context is sufficient to support an analyst assessment without turning a
single alert into a compromise verdict.
"""

from dataclasses import dataclass
from typing import Literal

AssessmentState = Literal[
    "Expected",
    "Requires Investigation",
    "Insufficient Evidence",
    "Security Concern",
]
Confidence = Literal["Low", "Medium", "High"]
EvidenceRelationship = Literal["direct", "corroborating", "contradicting"]


@dataclass(frozen=True)
class EvidenceItem:
    """A documented observation used by the analyst assessment."""

    source: str
    observation: str
    confidence: Confidence
    relationship: EvidenceRelationship = "direct"
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("evidence source cannot be blank")
        if not self.observation.strip():
            raise ValueError("evidence observation cannot be blank")
        if self.notes and not self.notes.strip():
            raise ValueError("evidence notes cannot be whitespace only")


@dataclass(frozen=True)
class AssessmentInput:
    """Context required to assess a detection without overclaiming."""

    detection_present: bool
    ownership_verified: bool = False
    authorization_verified: bool = False
    expected_activity_verified: bool = False
    timing_verified: bool = False
    network_reviewed: bool = False
    endpoint_reviewed: bool = False
    change_or_testing_checked: bool = False
    post_auth_reviewed: bool = False
    privileged_account: bool = False
    contradictory_evidence: bool = False
    evidence: tuple[EvidenceItem, ...] = ()


@dataclass(frozen=True)
class AnalystAssessment:
    """The analyst's current evidence-backed assessment."""

    assessment: AssessmentState
    confidence: Confidence
    classification: str
    rationale: str
    evidence: tuple[EvidenceItem, ...]
    evidence_gaps: tuple[str, ...]
    recommended_action: str


def assess_detection(case: AssessmentInput) -> AnalystAssessment:
    """Assess a detection using explicit context and evidence gaps.

    ``Expected`` is reserved for cases where the relevant contextual checks
    have been completed. Contradictory evidence prevents closure as expected.
    ``Security Concern`` is reserved for cases with strong independent evidence
    beyond the detection signal itself; the current input model deliberately
    does not manufacture that evidence, so unresolved cases remain investigative.
    """
    gaps: list[str] = []
    if not case.ownership_verified:
        gaps.append("asset or account ownership is not verified")
    if not case.authorization_verified:
        gaps.append("authorization for the activity is not verified")
    if not case.expected_activity_verified:
        gaps.append("expected activity or baseline is not verified")
    if not case.timing_verified:
        gaps.append("activity timing is not verified against expected use")
    if not case.network_reviewed:
        gaps.append("related network evidence has not been reviewed")
    if not case.endpoint_reviewed:
        gaps.append("endpoint or post-event evidence has not been reviewed")
    if not case.change_or_testing_checked:
        gaps.append("maintenance, deployment, change, or security-testing context has not been checked")
    if case.privileged_account and not case.post_auth_reviewed:
        gaps.append("privileged post-authentication activity has not been reviewed")
    if case.contradictory_evidence:
        gaps.append("evidence contains unresolved contradictions")

    if not case.detection_present:
        return AnalystAssessment(
            assessment="Expected",
            confidence="High",
            classification="No detection signal",
            rationale="No detection signal is present; no security conclusion is inferred from absent evidence.",
            evidence=case.evidence,
            evidence_gaps=tuple(gaps),
            recommended_action="Document the observation and continue routine monitoring if applicable",
        )

    if not case.ownership_verified or not case.authorization_verified:
        return AnalystAssessment(
            assessment="Insufficient Evidence",
            confidence="Low",
            classification="Unresolved detection",
            rationale="The detection identifies activity requiring review, but ownership and authorization are not established.",
            evidence=case.evidence,
            evidence_gaps=tuple(gaps),
            recommended_action="Continue investigation and verify ownership, authorization, and scope",
        )

    if case.contradictory_evidence:
        return AnalystAssessment(
            assessment="Requires Investigation",
            confidence="Medium",
            classification="Conflicting evidence",
            rationale="Relevant evidence conflicts, so the case cannot be closed as expected activity or elevated to a confirmed security conclusion.",
            evidence=case.evidence,
            evidence_gaps=tuple(gaps),
            recommended_action="Resolve contradictions using independent evidence before closure",
        )

    if gaps:
        return AnalystAssessment(
            assessment="Requires Investigation",
            confidence="Medium",
            classification="Suspicious activity requiring validation",
            rationale="The detection remains relevant, but one or more contextual or corroborating checks are incomplete.",
            evidence=case.evidence,
            evidence_gaps=tuple(gaps),
            recommended_action="Collect the remaining evidence and reassess",
        )

    return AnalystAssessment(
        assessment="Expected",
        confidence="High",
        classification="Authorized expected activity",
        rationale="Ownership, authorization, expected activity, timing, network, endpoint, change/testing, and post-authentication checks are complete with no unresolved contradictions.",
        evidence=case.evidence,
        evidence_gaps=(),
        recommended_action="Document the rationale and close if the applicable playbook permits",
    )
