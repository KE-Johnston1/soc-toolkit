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


def correlate_events(
    events: Iterable[LogEvent], *, window: timedelta = timedelta(minutes=5)
) -> list[CorrelationResult]:
    """Group observations by source and assess cross-source temporal overlap."""
    grouped: dict[str, list[LogEvent]] = {}
    for event in events:
        if event.source_ip is not None:
            grouped.setdefault(event.source_ip, []).append(event)

    results: list[CorrelationResult] = []
    for source_ip, group in sorted(grouped.items()):
        sources = tuple(sorted({event.evidence_source for event in group}))
        event_types = tuple(sorted({event.event_type for event in group}))
        timestamps = sorted(event.timestamp for event in group if event.timestamp is not None)
        temporal = bool(timestamps) and timestamps[-1] - timestamps[0] <= window

        if len(sources) >= 2 and temporal:
            assessment, confidence = "Correlated", "Medium"
            rationale = (
                "The same source IP appears in multiple evidence sources within the "
                "configured time window. This supports correlation but does not establish "
                "attribution or malicious intent."
            )
        elif len(sources) >= 2:
            assessment, confidence = "Correlated", "Low"
            rationale = (
                "The same source IP appears in multiple evidence sources, but the available "
                "timestamps do not establish temporal overlap."
            )
        else:
            assessment, confidence = "Observed", "Medium"
            rationale = "The source IP was observed in one evidence source; cross-source correlation is not established."

        results.append(
            CorrelationResult(
                source_ip=source_ip,
                event_count=len(group),
                evidence_sources=sources,
                event_types=event_types,
                temporal_correlation=temporal,
                assessment=assessment,
                confidence=confidence,
                rationale=rationale,
            )
        )
    return results
