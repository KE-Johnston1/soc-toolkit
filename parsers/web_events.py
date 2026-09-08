"""Parse synthetic web observations into structured SOC events."""

from datetime import datetime, timezone
from pathlib import Path
import re

from soc_toolkit.models import LogEvent

_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"webserver:\s+(?P<method>\S+)\s+(?P<path>\S+)\s+from\s+(?P<source_ip>[^\s]+)"
)


def parse_web_log(path: str | Path, *, year: int, tz: timezone) -> list[LogEvent]:
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
                destination_port=80,
                protocol="tcp",
                event_type="web_request",
                account=None,
                action=match.group("method").upper(),
                message=raw_line,
                evidence_source=source,
                raw_line=raw_line,
                metadata={"request_path": match.group("path")},
            )
        )
    return events
