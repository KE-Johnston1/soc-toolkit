"""Parse synthetic firewall observations into structured events."""

from datetime import datetime, timezone
from pathlib import Path
import re

from soc_toolkit.models import LogEvent

_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"firewall:\s+Blocked connection from (?P<source_ip>[^\s]+) to port (?P<destination_port>\d+)"
)


def parse_firewall_log(path: str | Path) -> list[LogEvent]:
    """Return validated firewall observations without inferring destination IP or protocol."""
    events: list[LogEvent] = []
    source = str(path)
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        match = _PATTERN.match(raw_line)
        if not match:
            continue
        timestamp = datetime.strptime(match.group("timestamp"), "%b %d %H:%M:%S").replace(
            year=2026, tzinfo=timezone.utc
        )
        events.append(
            LogEvent(
                timestamp=timestamp,
                source_ip=match.group("source_ip"),
                destination_ip=None,
                source_port=None,
                destination_port=int(match.group("destination_port")),
                protocol=None,
                event_type="firewall_block",
                account=None,
                action="blocked",
                message=raw_line,
                evidence_source=source,
                raw_line=raw_line,
                metadata={"disposition": "blocked"},
            )
        )
    return events
