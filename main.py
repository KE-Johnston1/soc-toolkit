"""Command-line entry point for the SOC Toolkit."""

import argparse
from datetime import timezone


def run_assessment() -> None:
    """Run a synthetic authentication detection through analyst assessment."""
    from detections.authentication import detect_repeated_auth_failures
    from parsers.auth_parser import parse_auth_log
    from soc_toolkit.assessment import AssessmentInput, EvidenceItem, assess_detection

    events = parse_auth_log("logs/auth.log", year=2026, tz=timezone.utc)
    detections = detect_repeated_auth_failures(events)

    if not detections:
        print("Assessment: Expected")
        print("Confidence: High")
        print("Rationale: No configured authentication detection was triggered.")
        return

    detection = detections[0]
    evidence = tuple(
        EvidenceItem(
            source="authentication detector",
            observation=item,
            confidence=detection.confidence,
            relationship="direct",
        )
        for item in detection.evidence
    )
    assessment = assess_detection(
        AssessmentInput(
            detection_present=True,
            evidence=evidence,
        )
    )

    print(f"Detection: {detection.rule_id}")
    print(f"Assessment: {assessment.assessment}")
    print(f"Confidence: {assessment.confidence}")
    print(f"Classification: {assessment.classification}")
    print(f"Recommended action: {assessment.recommended_action}")
    print(f"Rationale: {assessment.rationale}")
    if assessment.evidence_gaps:
        print("Evidence gaps:")
        for gap in assessment.evidence_gaps:
            print(f"  - {gap}")


def run_module(module: str) -> None:
    """Run one toolkit module while retaining legacy entry points."""
    if module == "log":
        from parsers import log_parser
        for event in log_parser.parse_auth_log():
            print(event)
    elif module == "firewall":
        from parsers import firewall_parser
        for event in firewall_parser.parse_firewall_log():
            print(event)
    elif module == "web":
        from parsers import web_parser
        for event in web_parser.parse_web_log():
            print(event)
    elif module == "correlate":
        from parsers import correlate_logs
        correlate_logs.correlate_logs()
    elif module == "reputation":
        from parsers import ip_reputation
        ip_reputation.check_ip_reputation()
    elif module == "assessment":
        run_assessment()
    else:
        raise ValueError("unknown module")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Toolkit CLI")
    parser.add_argument(
        "--module",
        choices=("log", "firewall", "web", "correlate", "reputation", "assessment"),
        help="Module to run",
    )
    args = parser.parse_args()

    if args.module:
        run_module(args.module)
        return

    print("Select a module to run:")
    options = {
        "1": "log",
        "2": "firewall",
        "3": "web",
        "4": "correlate",
        "5": "reputation",
        "6": "assessment",
    }
    for number, module in options.items():
        print(f"  {number}. {module}")

    choice = input("Enter number (1–6): ").strip()
    selected = options.get(choice)
    if selected:
        run_module(selected)
    else:
        print("[!] Invalid selection")


if __name__ == "__main__":
    main()
