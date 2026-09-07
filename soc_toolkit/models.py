"""Validated structured event models used by SOC Toolkit parsers and detections."""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from typing import Any


@dataclass(frozen=True)
class LogEvent:
    """A normalised log observation.

    The model records what a parser observed. It does not assign maliciousness
    or incident status; those decisions belong to later detection/triage logic.
    """

    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    event_type: str
    account: str | None
    action: str | None
    message: str
    evidence_source: str
    raw_line: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp is not None and self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware when provided")

        for field_name in ("source_ip", "destination_ip"):
            value = getattr(self, field_name)
            if value is not None:
                try:
                    ip_address(value)
                except ValueError as exc:
                    raise ValueError(f"invalid {field_name}: {value}") from exc

        for field_name in ("source_port", "destination_port"):
            value = getattr(self, field_name)
            if value is not None and not 1 <= value <= 65535:
                raise ValueError(f"{field_name} must be between 1 and 65535")

        if self.protocol is not None and not self.protocol.strip():
            raise ValueError("protocol cannot be blank when provided")
        if not self.event_type.strip():
            raise ValueError("event_type cannot be blank")
        if not self.message.strip():
            raise ValueError("message cannot be blank")
        if not self.evidence_source.strip():
            raise ValueError("evidence_source cannot be blank")
        if not self.raw_line.strip():
            raise ValueError("raw_line cannot be blank")

        if self.protocol is not None:
            object.__setattr__(self, "protocol", self.protocol.lower())
