"""Cross-source correlation for structured SOC log events."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from soc_toolkit.models import LogEvent


@dataclass(frozen=True)
class CorrelationResult:
    source_ip: str
    event_count: int
    evidence_sources: tuple[str, ...]
    event_types: tuple[str, ...]
    temporal_correlation: bool
    assessment: str
    confidence: str
    rationale: str


def correlate_events(events: Iterable[LogEvent], *, window: timedelta = timedelta(minutes=5)) -> list[CorrelationResult]:
    """Group events by source IP and assess how strongly they correlate.

    Correlation is deliberately narrower than attribution: seeing the same IP
    in multiple log sources does not prove that one actor caused every event.
    Temporal correlation is reported only when timestamps are present for the
    relevant events.
    """
    grouped: dict[str, list[LogEvent]] = {}
    for event in events:
        if event.source_ip is not None:
            grouped.setdefault(event.source_ip, []).append(event)

    results: list[CorrelationResult] = []
    for source_ip, group in sorted(grouped.items()):
        sources = tuple(sorted({event.evidence_source for event in group}))
        event_types = tuple(sorted({event.event_type for event in group}))
        timestamps = [event.timestamp for event in group if event.timestamp is not None]

        temporal = False
        if len(timestamps) >= 2:
            earliest, latest = min(timestamps), max(timestamps)
            temporal = latest - earliest <= window

        if len(sources) >= 2 and temporal:
            assessment = "Correlated"
            confidence = "Medium"
            rationale = "The same source IP appears in multiple evidence sources within the configured time window. This supports correlation but does not establish attribution or malicious intent."
        elif len(sources) >= 2:
            assessment = "Correlated"
            confidence = "Low"
            rationale = "The same source IP appears in multiple evidence sources, but complete timestamps are unavailable so temporal relationship cannot be established."
        else:
            assessment = "Observed"
            confidence = "Medium"
            rationale = "The source IP was observed in one evidence source; cross-source correlation is not established."

        results.append(CorrelationResult(source_ip, len(group), sources, event_types, temporal, assessment, confidence, rationale))

    return results
