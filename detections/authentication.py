"""Evidence-aware authentication detections."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_toolkit.models import LogEvent


@dataclass(frozen=True)
class DetectionResult:
    """A detection hypothesis, not a compromise verdict."""

    rule_id: str
    assessment: str
    confidence: str
    source_ip: str
    account: str | None
    failure_count: int
    evidence: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    rationale: str


def detect_repeated_auth_failures(
    events: list[LogEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[DetectionResult]:
    """Detect repeated SSH authentication failures from one source.

    A time-window conclusion is made only when all relevant events have
    timezone-aware timestamps. Without trustworthy timestamps, the function
    returns a lower-confidence count-based observation instead.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    failures = [
        event for event in events
        if event.event_type == "authentication_failure" and event.destination_port == 22
    ]
    grouped: dict[tuple[str, str | None], list[LogEvent]] = {}
    for event in failures:
        grouped.setdefault((event.source_ip or "unknown", event.account), []).append(event)

    results: list[DetectionResult] = []
    for (source_ip, account), group in grouped.items():
        timestamps = [event.timestamp for event in group]
        if all(timestamp is not None for timestamp in timestamps):
            ordered = sorted(group, key=lambda event: event.timestamp)  # type: ignore[arg-type]
            for start_index, start_event in enumerate(ordered):
                start = start_event.timestamp
                assert start is not None
                window_events = [
                    event for event in ordered[start_index:]
                    if event.timestamp is not None and event.timestamp - start <= window
                ]
                if len(window_events) >= threshold:
                    results.append(
                        DetectionResult(
                            rule_id="AUTH-REPEAT-001",
                            assessment="Requires Investigation",
                            confidence="Medium",
                            source_ip=source_ip,
                            account=account,
                            failure_count=len(window_events),
                            evidence=("repeated SSH authentication failures within a verified time window",),
                            evidence_gaps=("ownership, authorization, and post-authentication context remain separate investigation questions" ,),
                            rationale="The configured failure threshold was met within the configured time window; this is a detection lead, not proof of brute force or compromise.",
                        )
                    )
                    break
        elif len(group) >= threshold:
            results.append(
                DetectionResult(
                    rule_id="AUTH-REPEAT-001",
                    assessment="Requires Investigation",
                    confidence="Low",
                    source_ip=source_ip,
                    account=account,
                    failure_count=len(group),
                    evidence=("repeated SSH authentication failures were observed",),
                    evidence_gaps=("trustworthy timestamps are unavailable, so a time-window conclusion cannot be established",),
                    rationale="The configured failure count was reached, but the supplied log does not establish when the events occurred.",
                )
            )

    return results
