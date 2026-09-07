"""Parse synthetic web observations into structured SOC events."""

from pathlib import Path
import re

from soc_toolkit.models import LogEvent

_WEB_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"webserver:\s+GET\s+(?P<path>\S+)\s+from\s+(?P<source_ip>\S+)"
)


def parse_web_log(path: str | Path = "logs/web.log") -> list[LogEvent]:
    """Parse web requests without classifying them as malicious."""
    events: list[LogEvent] = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = _WEB_PATTERN.match(line)
        if not match:
            continue

        events.append(
            LogEvent(
                timestamp=None,
                source_ip=match.group("source_ip"),
                destination_ip=None,
                source_port=None,
                destination_port=None,
                protocol=None,
                event_type="web_request",
                account=None,
                action="GET",
                message=line,
                evidence_source=str(path),
                raw_line=raw_line,
                metadata={
                    "syslog_timestamp": match.group("timestamp"),
                    "request_path": match.group("path"),
                },
            )
        )
    return events
