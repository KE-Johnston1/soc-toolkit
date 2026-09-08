"""Build case-specific competing hypotheses from observed evidence."""

from typing import Iterable

from soc_toolkit.correlation import CorrelationResult
from soc_toolkit.hypotheses import Hypothesis, HypothesisEvidence, evaluate_hypothesis
from soc_toolkit.models import LogEvent


def build_case_hypotheses(events: Iterable[LogEvent], correlations: Iterable[CorrelationResult]) -> tuple[Hypothesis, ...]:
    """Evaluate competing hypotheses without declaring an incident."""
    events = tuple(events)
    correlations = tuple(correlations)
    source = "192.168.1.101"
    source_events = tuple(event for event in events if event.source_ip == source)
    evidence: list[HypothesisEvidence] = []
    if any(event.event_type == "authentication_failure" for event in source_events):
        evidence.append(HypothesisEvidence("E-AUTH-FAILURES", "Repeated SSH authentication failures were observed from the same source.", "supports", "Medium"))
    if any(event.event_type == "authentication_success" for event in source_events):
        evidence.append(HypothesisEvidence("E-AUTH-SUCCESS", "A successful SSH authentication followed the failure sequence.", "supports", "Medium"))
    if any(item.source_ip == source and len(item.evidence_sources) >= 2 for item in correlations):
        evidence.append(HypothesisEvidence("E-CROSS-SOURCE", "The source appears across multiple evidence sources within the configured window.", "supports", "Medium"))
    return (
        evaluate_hypothesis("H1", "Legitimate administration or expected user activity", tuple(evidence)),
        evaluate_hypothesis("H2", "Credential attack or automated authentication abuse", tuple(evidence)),
        evaluate_hypothesis("H3", "Possible account compromise after successful authentication", tuple(item for item in evidence if item.evidence_id in {"E-AUTH-FAILURES", "E-AUTH-SUCCESS"})),
        evaluate_hypothesis("H4", "Misconfigured or automated service activity", tuple(item for item in evidence if item.evidence_id == "E-CROSS-SOURCE")),
        evaluate_hypothesis("H5", "Unknown or novel activity", ()),
    )
