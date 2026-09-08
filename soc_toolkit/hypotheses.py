"""Evidence-aware hypothesis tracking for synthetic SOC investigations."""

from dataclasses import dataclass
from typing import Literal

HypothesisStatus = Literal["Open", "Supported", "Challenged", "Unresolved"]
Confidence = Literal["Low", "Medium", "High"]

_LEVELS = ("Low", "Medium", "High")

@dataclass(frozen=True)
class HypothesisEvidence:
    evidence_id: str
    observation: str
    relationship: Literal["supports", "challenges"]
    confidence: Confidence

    def __post_init__(self) -> None:
        if not self.evidence_id.strip() or not self.observation.strip():
            raise ValueError("evidence_id and observation cannot be blank")

@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    title: str
    status: HypothesisStatus
    confidence: Confidence
    rationale: str
    evidence: tuple[HypothesisEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.hypothesis_id.strip() or not self.title.strip() or not self.rationale.strip():
            raise ValueError("hypothesis_id, title, and rationale cannot be blank")


def evaluate_hypothesis(hypothesis_id: str, title: str, evidence: tuple[HypothesisEvidence, ...]) -> Hypothesis:
    """Evaluate one hypothesis from explicit supporting and challenging evidence."""
    supports = [item for item in evidence if item.relationship == "supports"]
    challenges = [item for item in evidence if item.relationship == "challenges"]
    if supports and challenges:
        status, confidence = "Unresolved", "Medium"
        rationale = "Supporting and challenging evidence are both present; further investigation is required."
    elif supports:
        status = "Supported"
        confidence = max((item.confidence for item in supports), key=_LEVELS.index)
        rationale = "Available evidence supports this hypothesis, but support is not proof that it is established as fact."
    elif challenges:
        status = "Challenged"
        confidence = max((item.confidence for item in challenges), key=_LEVELS.index)
        rationale = "Available evidence challenges this hypothesis; it should not be treated as established."
    else:
        status, confidence = "Open", "Low"
        rationale = "No evidence has yet been linked to this hypothesis."
    return Hypothesis(hypothesis_id, title, status, confidence, rationale, evidence)
