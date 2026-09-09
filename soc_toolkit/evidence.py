"""Typed evidence provenance for evidence-first SOC investigations."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

EvidenceType = Literal["observed", "correlated", "inferred", "hypothesis", "unknown"]
EvidenceRelationship = Literal["supports", "challenges", "neutral"]
Confidence = Literal["Low", "Medium", "High"]

_LEVELS = ("Low", "Medium", "High")


@dataclass(frozen=True)
class EvidenceRecord:
    """A traceable piece of evidence with an explicit provenance level."""

    evidence_id: str
    source: str
    observation: str
    evidence_type: EvidenceType
    confidence: Confidence
    relationship: EvidenceRelationship = "neutral"
    observed_at: datetime | None = None
    asset: str | None = None
    account: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("evidence_id", "source", "observation"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be blank")
        if self.observed_at is not None and self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware when provided")
        if self.notes and not self.notes.strip():
            raise ValueError("notes cannot be whitespace only")


@dataclass(frozen=True)
class EvidenceSummary:
    """Counts and coverage indicators for the evidence presented to an analyst."""

    total: int
    observed: int
    correlated: int
    inferred: int
    hypothesis: int
    unknown: int
    direct_sources: tuple[str, ...]
    evidence_gaps: tuple[str, ...]


def summarise_evidence(records: tuple[EvidenceRecord, ...]) -> EvidenceSummary:
    """Summarise evidence provenance without converting it into a verdict."""
    counts = {kind: 0 for kind in ("observed", "correlated", "inferred", "hypothesis", "unknown")}
    for record in records:
        counts[record.evidence_type] += 1

    gaps: list[str] = []
    if not records:
        gaps.append("no evidence records are available")
    if not any(record.evidence_type == "observed" for record in records):
        gaps.append("no direct observed evidence is represented")
    if not any(record.observed_at is not None for record in records):
        gaps.append("evidence timestamps are not represented")

    return EvidenceSummary(
        total=len(records),
        observed=counts["observed"],
        correlated=counts["correlated"],
        inferred=counts["inferred"],
        hypothesis=counts["hypothesis"],
        unknown=counts["unknown"],
        direct_sources=tuple(sorted({record.source for record in records if record.evidence_type == "observed"})),
        evidence_gaps=tuple(gaps),
    )


def strongest_confidence(records: tuple[EvidenceRecord, ...]) -> Confidence:
    """Return the strongest represented confidence level."""
    if not records:
        return "Low"
    return max((record.confidence for record in records), key=_LEVELS.index)
