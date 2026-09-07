"""Compatibility wrapper for the structured authentication parser."""

from pathlib import Path

from parsers.auth_parser import parse_auth_log

__all__ = ["parse_auth_log"]


if __name__ == "__main__":
    events = parse_auth_log(Path("logs/auth.log"))
    for event in events:
        print(event)
