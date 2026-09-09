"""Command-line entry point for the SOC Toolkit."""

import argparse
from datetime import datetime, timezone
from pathlib import Path


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
    evidence = tuple(EvidenceItem(source="authentication detector", observation=item, confidence=detection.confidence, relationship="direct") for item in detection.evidence)
    assessment = assess_detection(AssessmentInput(detection_present=True, evidence=evidence))
    print(f"Detection: {detection.rule_id}")
    print(f"Assessment: {assessment.assessment}")
    print(f"Confidence: {assessment.confidence}")
    print(f"Classification: {assessment.classification}")
    print(f"Recommended action: {assessment.recommended_action}")
    print(f"Rationale: {assessment.rationale}")
    if assessment.evidence_gaps:
        print("Evidence gaps:")
        for gap in assessment.evidence_gaps: print(f"  - {gap}")


def run_response() -> None:
    """Show a controlled response recommendation for a synthetic case."""
    from soc_toolkit.response import ResponseInput, recommend_response
    decision = recommend_response(ResponseInput("Requires Investigation", "Medium", escalation_level="Tier 2", evidence_gaps=("post-authentication activity has not been reviewed",)))
    print(f"Response: {decision.action}")
    print(f"Rationale: {decision.rationale}")
    for item in decision.evidence_requirements: print(f"  - {item}")


def run_case() -> None:
    """Show a synthetic case transition and decision-trail entry."""
    from soc_toolkit.case_management import CaseRecord, transition_case
    case = CaseRecord("CASE-DEMO-001", "ALERT-DEMO-001", datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc), assessment="Requires Investigation", evidence_gaps=["ownership requires verification"])
    transition_case(case, "Investigating", actor_role="SOC Analyst", rationale="Alert requires evidence collection before risk or closure decisions.", timestamp=datetime(2026, 9, 7, 12, 5, tzinfo=timezone.utc))
    print(f"Case: {case.case_id}")
    print(f"Status: {case.status}")
    print(f"Decision trail entries: {len(case.decision_trail)}")


def run_case_pack() -> None:
    """Load the Phase 1 multi-source case and display its evidence correlation."""
    from soc_toolkit.case_pipeline import load_multi_source_case
    case_dir = Path("cases") / "CASE-MULTI-001"
    result = load_multi_source_case(case_dir)
    print(f"Case: {result.case_id}")
    print(f"Alert: {result.alert_id}")
    print(f"Normalised events: {len(result.events)}")
    print(f"Evidence sources: {len({event.evidence_source for event in result.events})}")
    for correlation in result.correlations:
        print(f"Correlation: {correlation.source_ip} | {correlation.assessment} ({correlation.confidence}) | sources={len(correlation.evidence_sources)} | temporal={correlation.temporal_correlation}")
        print(f"  Rationale: {correlation.rationale}")


def run_pipeline() -> None:
    """Run the flagship synthetic SSH case through every decision layer."""
    from soc_toolkit.pipeline import PipelineInput, run_pipeline as execute_pipeline
    result = execute_pipeline(PipelineInput(case_id="CASE-SSH-001", alert_id="ALERT-SSH-001", auth_log_path="logs/pipeline-auth.log", privileged_account=True, asset_criticality="High", account_privilege="High", likelihood="Medium", business_impact="High"))
    print(f"Case: {result.case.case_id}")
    print(f"Detection signals: {len(result.detections)}")
    print(f"Assessment: {result.assessment.assessment} ({result.assessment.confidence})")
    print(f"Risk: {result.risk.overall_risk} ({result.risk.confidence})")
    print(f"Escalation: {result.escalation.level}")
    print(f"Response: {result.response.action}")
    print(f"Case status: {result.case.status}")
    print(f"Closure ready: {result.closure_ready}")
    print("Decision trail:")
    for event in result.case.decision_trail: print(f"  - {event.timestamp.isoformat()} | {event.action} | {event.rationale}")
    if result.case.evidence_gaps:
        print("Evidence gaps:")
        for gap in result.case.evidence_gaps: print(f"  - {gap}")


def run_scenarios() -> None:
    """Validate and summarise all Phase 3 synthetic scenario packs."""
    from soc_toolkit.scenario_cases import load_scenario_case
    root = Path("cases")
    scenario_ids = ("CASE-PHISH-001", "CASE-NET-001", "CASE-INSIDER-001")
    for case_id in scenario_ids:
        case = load_scenario_case(root / case_id / "scenario.json")
        print(f"{case.case_id}: {case.data['scenario']} | {case.data['assessment']} ({case.data['confidence']}) | risk={case.data['risk']} | escalation={case.data['escalation']} | response={case.data['response']}")
        print(f"  Evidence records: {len(case.evidence)} | Hypotheses: {len(case.data['hypotheses'])} | Gaps: closure remains case-specific")


def run_module(module: str) -> None:
    """Run one toolkit module while retaining legacy entry points."""
    if module == "log":
        from parsers import log_parser
        for event in log_parser.parse_auth_log(): print(event)
    elif module == "firewall":
        from parsers import firewall_parser
        firewall_parser.parse_firewall_log()
    elif module == "web":
        from parsers import web_parser
        web_parser.parse_web_log()
    elif module == "correlate":
        from parsers import correlate_logs
        correlate_logs.correlate_logs()
    elif module == "reputation":
        from parsers import ip_reputation
        ip_reputation.check_ip_reputation()
    elif module == "assessment": run_assessment()
    elif module == "response": run_response()
    elif module == "case": run_case()
    elif module == "case-pack": run_case_pack()
    elif module == "pipeline": run_pipeline()
    elif module == "scenarios": run_scenarios()
    else: raise ValueError("unknown module")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Toolkit CLI")
    modules = ("log", "firewall", "web", "correlate", "reputation", "assessment", "response", "case", "case-pack", "pipeline", "scenarios")
    parser.add_argument("--module", choices=modules, help="Module to run")
    args = parser.parse_args()
    if args.module:
        run_module(args.module)
        return
    print("Select a module to run:")
    options = {str(i): module for i, module in enumerate(modules, start=1)}
    for number, module in options.items(): print(f"  {number}. {module}")
    selected = options.get(input(f"Enter number (1–{len(modules)}): ").strip())
    if selected: run_module(selected)
    else: print("[!] Invalid selection")


if __name__ == "__main__":
    main()
