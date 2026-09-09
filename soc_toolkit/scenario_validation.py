"""Validation controls for reproducible SOC scenario packs."""

import json
from pathlib import Path

REQUIRED_SCENARIO_KEYS = {
    "case_id", "title", "scenario", "assessment", "confidence", "risk", "escalation",
    "response", "closure", "hypotheses", "evidence", "lessons_learned",
}


def validate_scenario(path: str | Path) -> list[str]:
    """Return validation errors; an empty list means the pack is structurally valid."""
    file_path = Path(path)
    if not file_path.is_file():
        return [f"scenario file does not exist: {file_path}"]
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"scenario JSON could not be loaded: {exc}"]
    if not isinstance(data, dict):
        return ["scenario root must be an object"]
    errors = [f"missing required field: {key}" for key in sorted(REQUIRED_SCENARIO_KEYS - data.keys())]
    for key in ("case_id", "title", "scenario", "assessment", "confidence", "risk", "escalation", "response", "closure"):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            errors.append(f"scenario field {key} must be a non-empty string")
    for key in ("hypotheses", "evidence", "lessons_learned"):
        if key in data and (not isinstance(data[key], list) or not data[key]):
            errors.append(f"{key} must be a non-empty list")
    return errors
