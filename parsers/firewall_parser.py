"""Parse synthetic firewall observations into structured SOC events."""

from pathlib import Path
import re

from soc_toolkit.models import LogEvent

_FIREWALL_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"firewall:\s+Blocked connection from (?P<source_ip>\S+) to port (?P<port>\d+)"
)


def parse_firewall_log(path: str | Path = "logs/firewall.log") -> list[LogEvent]:
    """Parse firewall block records without assigning malicious intent."""
    events: list[LogEvent] = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = _FIREWALL_PATTERN.match(line)
        if not match:
            continue
        events.append(LogEvent(timestamp=None, source_ip=match.group("source_ip"), destination_ip=None, source_port=None, destination_port=int(match.group("port")), protocol=None, event_type="firewall", account=None, action="blocked", message=line, evidence_source=str(path), raw_line=raw_line, metadata={"syslog_timestamp": match.group("timestamp")}))
    return events
