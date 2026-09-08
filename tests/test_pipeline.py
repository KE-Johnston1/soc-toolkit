from datetime import timezone
from pathlib import Path
import unittest

from detections.authentication import detect_repeated_auth_failures
from parsers.auth_parser import parse_auth_log
from soc_toolkit.pipeline import PipelineInput, run_pipeline


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.log = str(Path(__file__).parents[1] / "logs" / "pipeline-auth.log")
        self.case = str(Path(__file__).parents[1] / "cases" / "CASE-MULTI-001")

    def test_pipeline_fixture_produces_detection_signal(self):
        events = parse_auth_log(self.log, year=2026, tz=timezone.utc)
        self.assertEqual(len(events), 5)
        self.assertTrue(all(event.event_type == "authentication_failure" for event in events))
        detections = detect_repeated_auth_failures(events)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].failure_count, 5)
        self.assertEqual(detections[0].source_ip, "192.168.1.101")
        self.assertEqual(detections[0].account, "admin")

    def test_multisource_case_pack_flows_into_pipeline_correlation(self):
        result = run_pipeline(
            PipelineInput(
                case_id="CASE-MULTI-001",
                alert_id="ALERT-AUTH-001",
                case_path=self.case,
                privileged_account=True,
                asset_criticality="High",
                account_privilege="High",
                likelihood="Medium",
                business_impact="High",
            )
        )
        self.assertTrue(result.detections)
        self.assertEqual(len(result.events), 10)
        self.assertEqual(len(result.correlated_sources), 3)
        correlation = next(item for item in result.correlations if item.source_ip == "192.168.1.101")
        self.assertTrue(correlation.temporal_correlation)
        self.assertEqual(len(correlation.evidence_sources), 3)
        self.assertEqual(len(result.hypotheses), 5)
        self.assertEqual(result.hypotheses[-1].status, "Open")
        self.assertIn("not proof", result.hypotheses[1].rationale)
        self.assertEqual(result.assessment.assessment, "Insufficient Evidence")
        self.assertEqual(result.response.action, "Investigate")
        self.assertFalse(result.closure_ready)

    def test_unresolved_auth_alert_stays_investigative(self):
        result = run_pipeline(
            PipelineInput(
                case_id="CASE-PIPE-001",
                alert_id="ALERT-SSH-001",
                auth_log_path=self.log,
                privileged_account=True,
                asset_criticality="High",
                account_privilege="High",
                likelihood="Medium",
                business_impact="High",
            )
        )
        self.assertTrue(result.detections)
        self.assertEqual(result.assessment.assessment, "Insufficient Evidence")
        self.assertEqual(result.escalation.level, "Monitor")
        self.assertEqual(result.response.action, "Investigate")
        self.assertEqual(result.case.status, "Investigating")
        self.assertFalse(result.closure_ready)
        self.assertIn("pipeline-auth.log", result.correlated_sources[0])

    def test_stronger_synthetic_evidence_can_reach_containment(self):
        result = run_pipeline(
            PipelineInput(
                case_id="CASE-PIPE-002",
                alert_id="ALERT-MALWARE-001",
                auth_log_path=self.log,
                owner_verified=True,
                authorization_verified=True,
                expected_activity_verified=True,
                timing_verified=True,
                network_reviewed=True,
                endpoint_reviewed=True,
                change_or_testing_checked=True,
                post_auth_reviewed=True,
                privileged_account=True,
                malware_evidence=True,
                contradictory_evidence=True,
                containment_authorized=True,
                containment_safe=True,
                asset_criticality="High",
                account_privilege="High",
                data_sensitivity="High",
                likelihood="High",
                business_impact="High",
                financial_impact="Unknown",
            )
        )
        self.assertEqual(result.assessment.assessment, "Requires Investigation")
        self.assertEqual(result.escalation.level, "Incident Response")
        self.assertEqual(result.response.action, "Contain")
        self.assertFalse(result.closure_ready)


if __name__ == "__main__":
    unittest.main()
