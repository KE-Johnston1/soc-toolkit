"""Load and validate Phase 3 scenario case packs."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REQUIRED = ("case_id", "title", "scenario", "assessment", "confidence", "risk", "escalation", "response", "closure", "evidence", "hypotheses", "lessons_learned")

@dataclass(frozen=True)
class ScenarioCase:
    data: dict[str, Any]

    @property
    def case_id(self) -> str:
        return self.data["case_id"]

    @property
    def evidence(self) -> list[dict[str, Any]]:
        return self.data["evidence"]


def load_scenario_case(path: str | Path) -> ScenarioCase:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [key for key in _REQUIRED if key not in payload]
    if missing:
        raise ValueError(f"scenario case missing fields: {', '.join(missing)}")
    for key in ("case_id", "title", "scenario", "assessment", "confidence", "risk", "escalation", "response", "closure"):
        if not isinstance(payload[key], str) or not payload[key].strip():
            raise ValueError(f"scenario field {key} must be a non-empty string")
    if not isinstance(payload["evidence"], list) or not payload["evidence"]:
        raise ValueError("scenario evidence must be a non-empty list")
    if not isinstance(payload["hypotheses"], list) or not payload["hypotheses"]:
        raise ValueError("scenario hypotheses must be a non-empty list")
    for item in payload["evidence"]:
        if not all(isinstance(item.get(key), str) and item[key].strip() for key in ("id", "source", "observation", "type", "confidence", "relationship")):
            raise ValueError("each evidence record requires id, source, observation, type, confidence, and relationship")
    return ScenarioCase(payload)
