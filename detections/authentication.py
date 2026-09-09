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


def _build_result(
    *,
    source_ip: str,
    account: str | None,
    group: list[LogEvent],
    confidence: str,
    evidence: tuple[str, ...],
    evidence_gaps: tuple[str, ...],
    rationale: str,
) -> DetectionResult:
    """Build a consistent authentication detection result."""
    return DetectionResult(
        rule_id="AUTH-REPEAT-001",
        assessment="Requires Investigation",
        confidence=confidence,
        source_ip=source_ip,
        account=account,
        failure_count=len(group),
        evidence=evidence,
        evidence_gaps=evidence_gaps,
        rationale=rationale,
    )


def _within_window(group: list[LogEvent], window: timedelta) -> list[LogEvent] | None:
    """Return the first threshold-sized window, or ``None`` when timestamps are incomplete."""
    timestamps = [event.timestamp for event in group]
    if not all(timestamp is not None for timestamp in timestamps):
        return None

    ordered = sorted(group, key=lambda event: event.timestamp)  # type: ignore[arg-type]
    for start_index, start_event in enumerate(ordered):
        start = start_event.timestamp
        assert start is not None
        window_events = [
            event
            for event in ordered[start_index:]
            if event.timestamp is not None and event.timestamp - start <= window
        ]
        if window_events:
            return window_events
    return []


def detect_repeated_auth_failures(
    events: list[LogEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[DetectionResult]:
    """Detect repeated SSH authentication failures.

    Two related views are evaluated:

    * per-account repetition, useful for brute-force investigation; and
    * source-wide repetition across multiple accounts, useful for password
      spraying where an attacker rotates usernames to avoid per-account rules.

    A time-window conclusion is made only when all relevant events have
    timezone-aware timestamps. Without trustworthy timestamps, the function
    returns a lower-confidence count-based observation instead.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    failures = [
        event
        for event in events
        if event.event_type == "authentication_failure" and event.destination_port == 22
    ]
    by_account: dict[tuple[str, str | None], list[LogEvent]] = {}
    by_source: dict[str, list[LogEvent]] = {}
    for event in failures:
        source_ip = event.source_ip or "unknown"
        by_account.setdefault((source_ip, event.account), []).append(event)
        by_source.setdefault(source_ip, []).append(event)

    results: list[DetectionResult] = []

    # Per-account repetition: the original brute-force detection behaviour.
    for (source_ip, account), group in by_account.items():
        timestamps = [event.timestamp for event in group]
        if all(timestamp is not None for timestamp in timestamps):
            ordered = sorted(group, key=lambda event: event.timestamp)  # type: ignore[arg-type]
            for start_index, start_event in enumerate(ordered):
                start = start_event.timestamp
                assert start is not None
                window_events = [
                    event
                    for event in ordered[start_index:]
                    if event.timestamp is not None and event.timestamp - start <= window
                ]
                if len(window_events) >= threshold:
                    results.append(
                        _build_result(
                            source_ip=source_ip,
                            account=account,
                            group=window_events,
                            confidence="Medium",
                            evidence=("repeated SSH authentication failures within a verified time window",),
                            evidence_gaps=("ownership, authorization, and post-authentication context remain separate investigation questions",),
                            rationale="The configured failure threshold was met for one account within the configured time window; this is a detection lead, not proof of brute force or compromise.",
                        )
                    )
                    break
        elif len(group) >= threshold:
            results.append(
                _build_result(
                    source_ip=source_ip,
                    account=account,
                    group=group,
                    confidence="Low",
                    evidence=("repeated SSH authentication failures were observed",),
                    evidence_gaps=("trustworthy timestamps are unavailable, so a time-window conclusion cannot be established",),
                    rationale="The configured failure count was reached for one account, but the supplied log does not establish when the events occurred.",
                )
            )

    # Source-wide repetition: catches password spraying across usernames.
    for source_ip, group in by_source.items():
        accounts = {event.account for event in group}
        if len(accounts) < 2 or len(group) < threshold:
            continue

        timestamps = [event.timestamp for event in group]
        if all(timestamp is not None for timestamp in timestamps):
            ordered = sorted(group, key=lambda event: event.timestamp)  # type: ignore[arg-type]
            matched: list[LogEvent] = []
            for start_index, start_event in enumerate(ordered):
                start = start_event.timestamp
                assert start is not None
                candidate = [
                    event
                    for event in ordered[start_index:]
                    if event.timestamp is not None and event.timestamp - start <= window
                ]
                if len(candidate) >= threshold:
                    matched = candidate
                    break
            if matched:
                results.append(
                    _build_result(
                        source_ip=source_ip,
                        account=None,
                        group=matched,
                        confidence="Medium",
                        evidence=("repeated SSH authentication failures from one source across multiple accounts within a verified time window",),
                        evidence_gaps=("determine whether the source is authorised and review successful authentication or endpoint activity",),
                        rationale="The source generated repeated failures across multiple accounts, which is consistent with a password-spraying investigation pattern; it does not establish malicious intent or compromise.",
                    )
                )
        elif len(group) >= threshold:
            results.append(
                _build_result(
                    source_ip=source_ip,
                    account=None,
                    group=group,
                    confidence="Low",
                    evidence=("repeated SSH authentication failures from one source across multiple accounts were observed",),
                    evidence_gaps=("trustworthy timestamps are unavailable, so a time-window conclusion cannot be established",),
                    rationale="The source reached the configured failure count across multiple accounts, but the supplied log does not establish when the events occurred.",
                )
            )

    return results
