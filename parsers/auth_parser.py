"""Parse common SSH authentication log observations into structured events."""

from datetime import datetime, timezone
from pathlib import Path
import re

from soc_toolkit.models import LogEvent


_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<service>sshd)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<action>Failed password|Accepted password)\s+for\s+"
    r"(?P<account>invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<source_ip>[^\s]+)\s+port\s+(?P<source_port>\d+)"
)


def _parse_timestamp(value: str, *, year: int | None, tz: timezone | None) -> datetime | None:
    """Parse a syslog timestamp only when year and timezone are supplied."""
    if year is None or tz is None:
        return None
    return datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)


def parse_auth_log(
    path: str | Path = "logs/auth.log",
    *,
    year: int | None = None,
    tz: timezone | None = None,
) -> list[LogEvent]:
    """Return parsed SSH authentication observations.

    Syslog timestamps do not contain a year or timezone. By default the
    timestamp is therefore left as ``None`` rather than inventing precision.
    Malformed/non-matching lines are skipped because they are not safely
    normalisable by this parser.
    """
    events: list[LogEvent] = []
    source = str(path)

    with Path(path).open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            match = _AUTH_PATTERN.match(line)
            if not match:
                continue

            action = match.group("action")
            account = match.group("user")
            event_type = "authentication_failure" if action.startswith("Failed") else "authentication_success"

            events.append(
                LogEvent(
                    timestamp=_parse_timestamp(match.group("timestamp"), year=year, tz=tz),
                    source_ip=match.group("source_ip"),
                    destination_ip=None,
                    source_port=int(match.group("source_port")),
                    destination_port=22,
                    protocol="tcp",
                    event_type=event_type,
                    account=account,
                    action="failure" if event_type.endswith("failure") else "success",
                    message=line,
                    evidence_source=source,
                    raw_line=line,
                    metadata={
                        "service": match.group("service"),
                        "pid": match.group("pid"),
                        "invalid_user": bool(match.group("account")),
                    },
                )
            )

    return events
