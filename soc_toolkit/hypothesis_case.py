"""Build case-specific competing hypotheses from observed evidence."""

from typing import Iterable

from soc_toolkit.correlation import CorrelationResult
from soc_toolkit.hypotheses import Hypothesis, HypothesisEvidence, evaluate_hypothesis
from soc_toolkit.models import LogEvent


def _investigation_source(events: tuple[LogEvent, ...], correlations: tuple[CorrelationResult, ...]) -> str | None:
    """Choose the strongest source relationship without hard-coding an IP."""
    candidates = [
        item
        for item in correlations
        if len(item.evidence_sources) >= 2
    ]
    if candidates:
        return max(candidates, key=lambda item: (len(item.evidence_sources), item.event_count, item.source_ip)).source_ip
    source_counts: dict[str, int] = {}
    for event in events:
        if event.source_ip:
            source_counts[event.source_ip] = source_counts.get(event.source_ip, 0) + 1
    return max(source_counts, key=source_counts.get) if source_counts else None


def build_case_hypotheses(
    events: Iterable[LogEvent],
    correlations: Iterable[CorrelationResult],
) -> tuple[Hypothesis, ...]:
    """Evaluate competing explanations using the case's actual evidence."""
    events = tuple(events)
    correlations = tuple(correlations)
    source = _investigation_source(events, correlations)
    source_events = tuple(event for event in events if event.source_ip == source) if source else ()

    failures = any(event.event_type == "authentication_failure" for event in source_events)
    success = any(event.event_type == "authentication_success" for event in source_events)
    cross_source = any(
        item.source_ip == source and len(item.evidence_sources) >= 2
        for item in correlations
    )

    failure_evidence = HypothesisEvidence(
        "E-AUTH-FAILURES",
        "Repeated authentication failures were observed from the same source.",
        "supports",
        "Medium",
    )
    success_evidence = HypothesisEvidence(
        "E-AUTH-SUCCESS",
        "A successful authentication followed the failure sequence.",
        "supports",
        "Medium",
    )
    correlation_evidence = HypothesisEvidence(
        "E-CROSS-SOURCE",
        "The source appears across multiple evidence sources within the configured window.",
        "supports",
        "Medium",
    )
    legitimate_challenge = HypothesisEvidence(
        "E-UNVERIFIED-LEGITIMATE",
        "Expected ownership and authorization have not yet been independently established.",
        "challenges",
        "Low",
    )

    h1_evidence = tuple(item for item in (legitimate_challenge,) if not (not failures and not success))
    h2_evidence = tuple(item for item, present in ((failure_evidence, failures), (correlation_evidence, cross_source)) if present)
    h3_evidence = tuple(item for item, present in ((failure_evidence, failures), (success_evidence, success)) if present)
    h4_evidence = (correlation_evidence,) if cross_source else ()

    return (
        evaluate_hypothesis("H1", "Legitimate administration or expected user activity", h1_evidence),
        evaluate_hypothesis("H2", "Credential attack or automated authentication abuse", h2_evidence),
        evaluate_hypothesis("H3", "Possible account compromise after successful authentication", h3_evidence),
        evaluate_hypothesis("H4", "Misconfigured or automated service activity", h4_evidence),
        evaluate_hypothesis("H5", "Unknown or novel activity", ()),
    )
