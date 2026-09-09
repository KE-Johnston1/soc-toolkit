"""End-to-end synthetic SOC investigation pipeline."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detections.authentication import DetectionResult, detect_repeated_auth_failures
from parsers.auth_parser import parse_auth_log
from soc_toolkit.assessment import AssessmentInput, AnalystAssessment, EvidenceItem, assess_detection
from soc_toolkit.case_loader import CasePack, load_case_pack
from soc_toolkit.case_management import CaseRecord, transition_case
from soc_toolkit.correlation import CorrelationResult, correlate_events
from soc_toolkit.escalation import EscalationDecision, EscalationInput, recommend_escalation
from soc_toolkit.evidence import EvidenceRecord, EvidenceSummary, summarise_evidence
from soc_toolkit.hypotheses import Hypothesis
from soc_toolkit.hypothesis_case import build_case_hypotheses
from soc_toolkit.investigation_context import InvestigationContext, assess_vulnerability
from soc_toolkit.response import ResponseDecision, ResponseInput, recommend_response
from soc_toolkit.risk import RiskAssessment, RiskInput, assess_risk
from soc_toolkit.models import LogEvent


@dataclass(frozen=True)
class PipelineInput:
    case_id: str
    alert_id: str
    auth_log_path: str = "logs/pipeline-auth.log"
    case_path: str | None = None
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
    investigation_context: InvestigationContext = InvestigationContext()
    created_at: datetime = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class CaseSummary:
    case: CaseRecord
    detections: tuple[DetectionResult, ...]
    correlated_sources: tuple[str, ...]
    correlations: tuple[CorrelationResult, ...]
    events: tuple[LogEvent, ...]
    evidence_records: tuple[EvidenceRecord, ...]
    evidence_summary: EvidenceSummary
    hypotheses: tuple[Hypothesis, ...]
    assessment: AnalystAssessment
    risk: RiskAssessment
    escalation: EscalationDecision
    response: ResponseDecision
    vulnerability_relevance: str
    vulnerability_gaps: tuple[str, ...]
    investigation_context: InvestigationContext
    closure_ready: bool


def _load_events(case: PipelineInput) -> tuple[LogEvent, ...]:
    if case.case_path:
        pack: CasePack = load_case_pack(case.case_path)
        if pack.case_id != case.case_id or pack.alert_id != case.alert_id:
            raise ValueError("pipeline identifiers do not match the case-pack alert")
        return pack.events

    path = Path(case.auth_log_path)
    if not path.exists():
        raise FileNotFoundError(f"authentication log not found: {path}")
    return tuple(parse_auth_log(path, year=case.created_at.year, tz=case.created_at.tzinfo))


def _build_evidence_records(
    events: tuple[LogEvent, ...],
    correlations: tuple[CorrelationResult, ...],
) -> tuple[EvidenceRecord, ...]:
    """Represent observations and correlations with explicit provenance."""
    records: list[EvidenceRecord] = []
    for index, event in enumerate(events, start=1):
        records.append(
            EvidenceRecord(
                evidence_id=f"OBS-{index:03d}",
                source=event.evidence_source,
                observation=event.message,
                evidence_type="observed",
                confidence="High",
                relationship="neutral",
                observed_at=event.timestamp,
                asset=event.destination_ip,
                account=event.account,
            )
        )
    for correlation in correlations:
        if len(correlation.evidence_sources) >= 2:
            records.append(
                EvidenceRecord(
                    evidence_id=f"CORR-{correlation.source_ip}",
                    source=", ".join(correlation.evidence_sources),
                    observation=correlation.rationale,
                    evidence_type="correlated",
                    confidence=correlation.confidence,
                    relationship="neutral",
                    observed_at=None,
                    notes="Correlation describes a relationship between observations; it does not establish attribution or intent.",
                )
            )
    return tuple(records)


def run_pipeline(case: PipelineInput) -> CaseSummary:
    """Run one synthetic case through detection, correlation and decision layers."""
    if case.created_at.tzinfo is None:
        raise ValueError("created_at must be timezone-aware")
    if not case.case_id.strip() or not case.alert_id.strip():
        raise ValueError("case_id and alert_id cannot be blank")

    events = _load_events(case)
    auth_events = tuple(event for event in events if event.event_type.startswith("authentication_"))
    detections = tuple(detect_repeated_auth_failures(list(auth_events)))
    correlations = tuple(correlate_events(events, window=timedelta(minutes=5)))
    evidence_records = _build_evidence_records(events, correlations)
    evidence_summary = summarise_evidence(evidence_records)
    hypotheses = build_case_hypotheses(events, correlations)
    vulnerability_relevance, vulnerability_gaps = assess_vulnerability(case.investigation_context.vulnerability)

    evidence: list[EvidenceItem] = []
    for detection in detections:
        evidence.extend(
            EvidenceItem("authentication detector", item, detection.confidence, "direct")
            for item in detection.evidence
        )
    for correlation in correlations:
        if len(correlation.evidence_sources) >= 2:
            evidence.append(
                EvidenceItem(
                    "cross-source correlation",
                    correlation.rationale,
                    correlation.confidence,
                    "corroborating",
                )
            )

    assessment = assess_detection(
        AssessmentInput(
            detection_present=bool(detections),
            ownership_verified=case.owner_verified,
            authorization_verified=case.authorization_verified,
            expected_activity_verified=case.expected_activity_verified,
            timing_verified=case.timing_verified,
            network_reviewed=case.network_reviewed or any(e.event_type == "firewall_block" for e in events),
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
            legal_regulatory_consideration=case.legal_privacy_consideration or case.investigation_context.legal_privacy.consideration_present,
            cve_relevance=case.cve_relevance if case.cve_relevance != "Unknown" else vulnerability_relevance,
            cvss_severity=case.cvss_severity if case.cvss_severity != "Unknown" else case.investigation_context.vulnerability.cvss_severity,
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
            sensitive_data_involved=case.sensitive_data_involved or case.investigation_context.impact.data_sensitivity == "High",
            legal_privacy_consideration=case.legal_privacy_consideration or case.investigation_context.legal_privacy.consideration_present,
            repeated_related_alerts=case.multiple_accounts,
        )
    )

    combined_gaps = tuple(dict.fromkeys(assessment.evidence_gaps + risk.evidence_gaps + escalation.evidence_gaps + vulnerability_gaps))
    closure_rationale = "Verified expected activity with no unresolved evidence gaps." if assessment.assessment == "Expected" and not combined_gaps else ""
    response = recommend_response(
        ResponseInput(
            assessment=assessment.assessment,
            confidence=assessment.confidence,
            escalation_level=escalation.level,
            evidence_gaps=combined_gaps,
            containment_authorized=case.containment_authorized,
            containment_safe=case.containment_safe,
            remediation_authorized=case.remediation_authorized,
            recovery_ready=case.recovery_ready,
            closure_criteria_met=assessment.assessment == "Expected" and not combined_gaps,
            closure_rationale=closure_rationale,
        )
    )

    record = CaseRecord(
        case_id=case.case_id,
        alert_id=case.alert_id,
        created_at=case.created_at,
        owner="SOC Analyst",
        assessment=assessment.assessment,
        risk=risk.overall_risk,
        escalation=escalation.level,
        response=response.action,
        evidence_gaps=list(combined_gaps),
        closure_rationale=closure_rationale,
    )

    transition_case(
        record,
        "Investigating",
        actor_role="SOC Analyst",
        rationale="Detection, correlated evidence, and competing hypotheses require an evidence-backed assessment before disruptive response or closure.",
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
    elif response.action == "Close":
        transition_case(
            record,
            "Closed",
            actor_role="SOC Analyst",
            rationale=closure_rationale,
            evidence_source="analyst assessment",
            confidence=assessment.confidence,
            timestamp=case.created_at + timedelta(minutes=2),
        )

    correlated_sources = sorted({event.evidence_source for event in events})
    return CaseSummary(
        case=record,
        detections=detections,
        correlated_sources=tuple(correlated_sources),
        correlations=correlations,
        events=events,
        evidence_records=evidence_records,
        evidence_summary=evidence_summary,
        hypotheses=hypotheses,
        assessment=assessment,
        risk=risk,
        escalation=escalation,
        response=response,
        vulnerability_relevance=vulnerability_relevance,
        vulnerability_gaps=vulnerability_gaps,
        investigation_context=case.investigation_context,
        closure_ready=response.action == "Close" and record.status == "Closed",
    )
