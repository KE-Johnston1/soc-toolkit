"""Phase 1 multi-source case orchestration."""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from soc_toolkit.case_loader import CasePack, load_case_pack
from soc_toolkit.correlation import CorrelationResult, correlate_events
from soc_toolkit.models import LogEvent


@dataclass(frozen=True)
class MultiSourceCase:
    """Loaded case-pack evidence plus its cross-source correlation results."""

    case_id: str
    alert_id: str
    source_ip: str
    events: tuple[LogEvent, ...]
    correlations: tuple[CorrelationResult, ...]


def load_multi_source_case(
    case_dir: str | Path, *, window_minutes: int = 5
) -> MultiSourceCase:
    """Load one case pack and correlate its normalised evidence."""
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    pack: CasePack = load_case_pack(case_dir)
    source_ip = str(pack.alert["source_ip"]) if "source_ip" in pack.alert else "unknown"
    correlations = tuple(
        correlate_events(pack.events, window=timedelta(minutes=window_minutes))
    )
    return MultiSourceCase(
        case_id=pack.case_id,
        alert_id=pack.alert_id,
        source_ip=source_ip,
        events=pack.events,
        correlations=correlations,
    )
