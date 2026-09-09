"""Small, auditable metrics for synthetic SOC case collections."""

from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class CaseMetricSummary:
    total_cases: int
    assessment_counts: dict[str, int]
    escalation_counts: dict[str, int]
    response_counts: dict[str, int]
    closure_ready: int
    unresolved_cases: int


def summarise_cases(cases: Iterable[dict]) -> CaseMetricSummary:
    items = list(cases)
    if not items:
        raise ValueError("at least one case is required")
    assessments: dict[str, int] = {}
    escalations: dict[str, int] = {}
    responses: dict[str, int] = {}
    closure_ready = 0
    unresolved = 0
    for case in items:
        for bucket, key in ((assessments, "assessment"), (escalations, "escalation"), (responses, "response")):
            value = str(case.get(key, "Unknown"))
            bucket[value] = bucket.get(value, 0) + 1
        if bool(case.get("closure_ready", False)):
            closure_ready += 1
        if case.get("assessment") in {"Requires Investigation", "Insufficient Evidence", "Security Concern"}:
            unresolved += 1
    return CaseMetricSummary(len(items), assessments, escalations, responses, closure_ready, unresolved)
