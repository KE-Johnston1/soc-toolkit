"""Phase 1 multi-source case orchestration."""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from parsers.auth_parser import parse_auth_log
from parsers.firewall_parser import parse_firewall_log
from parsers.web_parser import parse_web_log
from soc_toolkit.correlation import CorrelationResult, correlate_events


@dataclass(frozen=True)
class MultiSourceCase:
    case_id: str
    alert_id: str
    source_ip: str
    events: tuple[Any, ...]
    correlations: tuple[CorrelationResult, ...]


def load_multi_source_case(case_dir: str | Path, *, window_minutes: int = 5) -> MultiSourceCase:
    """Load the Phase 1 case pack and correlate its evidence sources."""
    root = Path(case_dir)
    alert_path = root / "alert.json"
    auth_path = root / "auth.log"
    firewall_path = root / "firewall.log"
    web_path = root / "web.log"

    import json
    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    for field in ("case_id", "alert_id", "source_ip"):
        if not isinstance(alert.get(field), str) or not alert[field].strip():
            raise ValueError(f"alert field {field!r} is required")

    events = (
        parse_auth_log(auth_path, year=2026, tz=__import__("datetime").timezone.utc)
        + parse_firewall_log(firewall_path)
        + parse_web_log(web_path)
    )
    correlations = tuple(correlate_events(events, window=timedelta(minutes=window_minutes)))
    return MultiSourceCase(
        case_id=alert["case_id"],
        alert_id=alert["alert_id"],
        source_ip=alert["source_ip"],
        events=tuple(events),
        correlations=correlations,
    )
