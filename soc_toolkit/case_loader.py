"""Load reproducible synthetic SOC case packs."""

from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
import json

from parsers.auth_parser import parse_auth_log
from parsers.firewall_events import parse_firewall_log
from parsers.web_events import parse_web_log
from soc_toolkit.models import LogEvent


@dataclass(frozen=True)
class CasePack:
    case_id: str
    alert_id: str
    title: str
    severity: str
    events: tuple[LogEvent, ...]
    alert: dict[str, object]


def load_case_pack(case_path: str | Path) -> CasePack:
    """Load alert metadata and all supported evidence sources from one case directory."""
    root = Path(case_path)
    alert = json.loads((root / "alert.json").read_text(encoding="utf-8"))
    required = ("case_id", "alert_id", "title", "severity", "timestamp")
    missing = [field for field in required if not str(alert.get(field, "")).strip()]
    if missing:
        raise ValueError(f"case alert is missing required fields: {', '.join(missing)}")

    timestamp = str(alert["timestamp"])
    if not timestamp.endswith("Z"):
        raise ValueError("case alert timestamp must use UTC Z notation")
    year = int(timestamp[:4])
    events: list[LogEvent] = []
    auth = root / "auth.log"
    firewall = root / "firewall.log"
    web = root / "web.log"
    if auth.exists():
        events.extend(parse_auth_log(auth, year=year, tz=timezone.utc))
    if firewall.exists():
        events.extend(parse_firewall_log(firewall, year=year, tz=timezone.utc))
    if web.exists():
        events.extend(parse_web_log(web, year=year, tz=timezone.utc))
    if not events:
        raise ValueError("case pack contains no supported evidence events")

    return CasePack(
        case_id=str(alert["case_id"]),
        alert_id=str(alert["alert_id"]),
        title=str(alert["title"]),
        severity=str(alert["severity"]),
        events=tuple(sorted(events, key=lambda event: event.timestamp or timestamp)),
        alert=alert,
    )
