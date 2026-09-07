"""End-to-end synthetic SOC investigation pipeline.

This module composes detection, assessment, risk, escalation, response, and
case-management layers. It uses caller-supplied evidence only and performs no
live collection or automated containment.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from detections.authentication import DetectionResult, detect_repeated_auth_failures
from parsers.auth_parser import parse_auth_log
from soc_toolkit.assessment import AssessmentInput, AnalystAssessment, EvidenceItem, assess_detection
from soc_toolkit.case_management import CaseRecord, transition_case
from soc_toolkit.escalation import EscalationDecision, EscalationInput, recommend_escalation
from soc_toolkit.response import ResponseDecision, ResponseInput, recommend_response
from soc_toolkit.risk import RiskAssessment, RiskInput, assess_risk


@dataclass(frozen=True)
class PipelineInput:
    case_id: str
    alert_id: str
    auth_log_path: str
    owner_verified: bool = False
    authorization_verified: bool = False
    expected_activity_verified: bool = False
    timing_verified: bool = False
    network_reviewed: bool = False
    endpoint_reviewed: bool = False
    change_or_testing_checked: bool = False
    post_auth_reviewed: bool = False
    privileged_account: bool = False
    contradictory_evidence: bool = False
    multiple_accounts: bool = False
    confirmed_malicious_infrastructure: bool = False
    malware_evidence: bool = False
    persistence_evidence: bool = False
    c2_evidence: bool = False
    exfiltration_evidence: bool = False
    sensitive_data_involved: bool = False
    legal_privacy_consideration: bool = False
    containment_authorized: bool = False
    containment_safe: bool = False
    remediation_authorized: bool = False
    recovery_ready: bool = False
    asset_criticality: str = "Unknown"
    account_privilege: str = "Unknown"
    data_sensitivity: str = "Unknown"
    likelihood: str = "Unknown"
    business_impact: str = "Unknown"
    financial_impact: str = "Unknown"
    financial_basis: str = "Unknown"
    cve_relevance: str = "Unknown"
    cvss_severity: str = "Unknown"
    assessment_confidence: str = "Low"
    created_at: datetime = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class CaseSummary:
    case: CaseRecord
    detections: tuple[DetectionResult, ...]
    correlated_sources: tuple[str, ...]
    assessment: AnalystAssessment
    risk: RiskAssessment
    escalation: EscalationDecision
    response: ResponseDecision
    closure_ready: bool


def run_pipeline(case: PipelineInput) -> CaseSummary:
    """Run one synthetic authentication case through the full decision path."""
    if case.created_at.tzinfo is None:
        raise ValueError("created_at must be timezone-aware")

    events = parse_auth_log(case.auth_log_path, year=case.created_at.year, tz=case.created_at.tzinfo)
    detections = tuple(detect_repeated_auth_failures(events))

    evidence: list[EvidenceItem] = []
    if detections:
        detection = detections[0]
        evidence.extend(
            EvidenceItem(
                source="authentication detector",
                observation=item,
                confidence=detection.confidence,
                relationship="direct",
            )
            for item in detection.evidence
        )
    if case.network_reviewed:
        evidence.append(EvidenceItem("network review", "Related network evidence was reviewed.", "Medium", "corroborating"))
    if case.endpoint_reviewed:
        evidence.append(EvidenceItem("endpoint review", "Related endpoint evidence was reviewed.", "Medium", "corroborating"))

    assessment = assess_detection(
        AssessmentInput(
            detection_present=bool(detections),
            ownership_verified=case.owner_verified,
            authorization_verified=case.authorization_verified,
            expected_activity_verified=case.expected_activity_verified,
            timing_verified=case.timing_verified,
            network_reviewed=case.network_reviewed,
            endpoint_reviewed=case.endpoint_reviewed,
            change_or_testing_checked=case.change_or_testing_checked,
            post_auth_reviewed=case.post_auth_reviewed,
            privileged_account=case.privileged_account,
            contradictory_evidence=case.contradictory_evidence,
            evidence=tuple(evidence),
        )
    )

    risk = assess_risk(
        RiskInput(
            asset_criticality=case.asset_criticality,
            account_privilege=case.account_privilege,
            data_sensitivity=case.data_sensitivity,
            likelihood=case.likelihood,
            business_impact=case.business_impact,
            financial_impact=case.financial_impact,
            financial_basis=case.financial_basis,
            legal_regulatory_consideration=case.legal_privacy_consideration,
            cve_relevance=case.cve_relevance,
            cvss_severity=case.cvss_severity,
            confidence=case.assessment_confidence,
        )
    )

    escalation = recommend_escalation(
        EscalationInput(
            assessment=assessment.assessment,
            confidence=assessment.confidence,
            privileged_account=case.privileged_account,
            multiple_accounts=case.multiple_accounts,
            confirmed_malicious_infrastructure=case.confirmed_malicious_infrastructure,
            malware_evidence=case.malware_evidence,
            persistence_evidence=case.persistence_evidence,
            c2_evidence=case.c2_evidence,
            exfiltration_evidence=case.exfiltration_evidence,
            business_impact=case.business_impact,
            sensitive_data_involved=case.sensitive_data_involved,
            legal_privacy_consideration=case.legal_privacy_consideration,
            containment_risk=case.containment_risk if hasattr(case, "containment_risk") else False,
            repeated_related_alerts=case.multiple_accounts,
        )
    )

    response = recommend_response(
        ResponseInput(
            assessment=assessment.assessment,
            confidence=assessment.confidence,
            escalation_level=escalation.level,
            evidence_gaps=assessment.evidence_gaps + risk.evidence_gaps,
            containment_authorized=case.containment_authorized,
            containment_safe=case.containment_safe,
            remediation_authorized=case.remediation_authorized,
            recovery_ready=case.recovery_ready,
            closure_criteria_met=assessment.assessment == "Expected" and not assessment.evidence_gaps and not risk.evidence_gaps,
            closure_rationale=("Verified expected activity with no unresolved evidence gaps." if assessment.assessment == "Expected" and not risk.evidence_gaps else ""),
        )
    )

    gaps = list(dict.fromkeys(assessment.evidence_gaps + risk.evidence_gaps + escalation.evidence_gaps))
    record = CaseRecord(
        case_id=case.case_id,
        alert_id=case.alert_id,
        created_at=case.created_at,
        owner="SOC Analyst",
        assessment=assessment.assessment,
        risk=risk.overall_risk,
        escalation=escalation.level,
        response=response.action,
        evidence_gaps=gaps,
        closure_rationale=("Verified expected activity with no unresolved evidence gaps." if response.action == "Close" else ""),
    )

    transition_case(
        record,
        "Investigating",
        actor_role="SOC Analyst",
        rationale="Detection and contextual evidence require an evidence-backed assessment before disruptive response or closure.",
        evidence_source="synthetic case pipeline",
        confidence=assessment.confidence,
        timestamp=case.created_at + timedelta(minutes=1),
    )
    if escalation.level in {"Tier 2", "Incident Response", "Management/Legal/Privacy"}:
        transition_case(
            record,
            "Escalated",
            actor_role="SOC Analyst",
            rationale=escalation.rationale,
            evidence_source="risk and escalation assessment",
            confidence=assessment.confidence,
            timestamp=case.created_at + timedelta(minutes=2),
        )

    return CaseSummary(
        case=record,
        detections=detections,
        correlated_sources=tuple(
            sorted({"authentication log", *("network evidence",) if case.network_reviewed else (), *("endpoint evidence",) if case.endpoint_reviewed else ()})
        ),
        assessment=assessment,
        risk=risk,
        escalation=escalation,
        response=response,
        closure_ready=response.action == "Close",
    )
