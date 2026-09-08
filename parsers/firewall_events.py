"""Parse synthetic firewall observations into structured SOC events."""

from datetime import datetime, timezone
from pathlib import Path
import re

from soc_toolkit.models import LogEvent

_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"firewall:\s+(?P<action>Blocked connection)\s+from\s+"
    r"(?P<source_ip>[^\s]+)\s+to\s+port\s+(?P<destination_port>\d+)"
)


def parse_firewall_log(path: str | Path, *, year: int, tz: timezone) -> list[LogEvent]:
    events: list[LogEvent] = []
    source = str(path)
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        match = _PATTERN.match(raw_line)
        if not match:
            continue
        timestamp = datetime.strptime(
            f"{year} {match.group('timestamp')}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=tz)
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
            )
        )
    return events
