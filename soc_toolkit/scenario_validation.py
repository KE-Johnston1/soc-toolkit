"""Validation controls for reproducible SOC scenario packs."""

import json
from pathlib import Path

REQUIRED_SCENARIO_KEYS = {
    "case_id", "scenario", "assessment", "confidence", "risk", "escalation", "response", "hypotheses", "evidence"
}


def validate_scenario(path: str | Path) -> list[str]:
    """Return validation errors; an empty list means the pack is structurally valid."""
    file_path = Path(path)
    errors: list[str] = []
    if not file_path.is_file():
        return [f"scenario file does not exist: {file_path}"]
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"scenario JSON could not be loaded: {exc}"]
    if not isinstance(data, dict):
        return ["scenario root must be an object"]
    missing = sorted(REQUIRED_SCENARIO_KEYS - data.keys())
    errors.extend(f"missing required field: {key}" for key in missing)
    if not isinstance(data.get("hypotheses", []), list):
        errors.append("hypotheses must be a list")
    if not isinstance(data.get("evidence", []), list):
        errors.append("evidence must be a list")
    return errors
