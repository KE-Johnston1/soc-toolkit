"""Command-line entry point for the structured SOC Toolkit workflow."""

import argparse
from pathlib import Path

from detections.authentication import detect_repeated_authentication_failures
from parsers.auth_parser import parse_auth_log
from parsers.firewall_parser import parse_firewall_log
from parsers.web_parser import parse_web_log
from soc_toolkit.correlation import correlate_events


def load_events() -> list:
    """Load supported synthetic log sources into one event stream."""
    events = []
    for parser, path in (
        (parse_auth_log, Path("logs/auth.log")),
        (parse_firewall_log, Path("logs/firewall.log")),
        (parse_web_log, Path("logs/web.log")),
    ):
        if path.exists():
            events.extend(parser(path))
    return events


def run_module(module: str) -> None:
    events = load_events()

    if module == "log":
        auth_events = [e for e in events if e.evidence_source.endswith("auth.log")]
        print(f"Observed {len(auth_events)} authentication events.")
        for event in auth_events:
            print(f"{event.event_type}: source={event.source_ip} account={event.account} action={event.action}")
    elif module == "firewall":
        firewall_events = [e for e in events if e.evidence_source.endswith("firewall.log")]
        print(f"Observed {len(firewall_events)} firewall events.")
        for event in firewall_events:
            print(f"{event.action}: source={event.source_ip} destination_port={event.destination_port}")
    elif module == "web":
        web_events = [e for e in events if e.event_type == "web_request"]
        print(f"Observed {len(web_events)} web requests.")
        for event in web_events:
            print(f"{event.action}: source={event.source_ip} path={event.metadata.get('request_path')}")
    elif module == "correlate":
        for result in correlate_events(events):
            print(f"{result.assessment}: {result.source_ip} sources={', '.join(result.evidence_sources)} confidence={result.confidence}")
    elif module == "detect":
        auth_events = [e for e in events if e.event_type.startswith("authentication_")]
        result = detect_repeated_authentication_failures(auth_events)
        if result is None:
            print("No configured repeated-authentication detection fired.")
        else:
            print(f"{result.assessment}: {result.rule_id} confidence={result.confidence}")
            print(result.rationale)
            for gap in result.evidence_gaps:
                print(f"Evidence gap: {gap}")
    else:
        raise ValueError(f"unsupported module: {module}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evidence-aware SOC Toolkit CLI")
    parser.add_argument("--module", choices=("log", "firewall", "web", "correlate", "detect"), default="detect")
    args = parser.parse_args()
    run_module(args.module)


if __name__ == "__main__":
    main()
