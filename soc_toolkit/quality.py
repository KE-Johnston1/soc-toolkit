"""Deterministic detection-quality checks for synthetic SOC cases."""

from dataclasses import dataclass
from typing import Literal

Outcome = Literal["True Positive", "False Positive", "True Negative", "False Negative"]

@dataclass(frozen=True)
class DetectionCheck:
    case_id: str
    rule_id: str
    detection_expected: bool
    detection_observed: bool
    rationale: str

    def __post_init__(self) -> None:
        if not self.case_id.strip() or not self.rule_id.strip() or not self.rationale.strip():
            raise ValueError("case_id, rule_id, and rationale cannot be blank")

    @property
    def outcome(self) -> Outcome:
        if self.detection_expected and self.detection_observed:
            return "True Positive"
        if self.detection_expected and not self.detection_observed:
            return "False Negative"
        if not self.detection_expected and self.detection_observed:
            return "False Positive"
        return "True Negative"

@dataclass(frozen=True)
class DetectionQuality:
    total: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float | None
    recall: float | None
    tuning_notes: tuple[str, ...]

def evaluate_detection_quality(checks: list[DetectionCheck]) -> DetectionQuality:
    if not checks:
        raise ValueError("at least one detection check is required")
    counts = {outcome: 0 for outcome in ("True Positive", "False Positive", "True Negative", "False Negative")}
    for check in checks:
        counts[check.outcome] += 1
    tp, fp, tn, fn = (counts["True Positive"], counts["False Positive"], counts["True Negative"], counts["False Negative"])
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    notes: list[str] = []
    if fp:
        notes.append("Review false-positive cases and confirm whether threshold, scope, or contextual filters should be tuned.")
    if fn:
        notes.append("Review false-negative cases before changing thresholds; missing telemetry or overly narrow detection scope may be responsible.")
    if not notes:
        notes.append("No false-positive or false-negative outcomes were identified in the supplied synthetic checks; continue monitoring with additional cases.")
    return DetectionQuality(len(checks), tp, fp, tn, fn, precision, recall, tuple(notes))
