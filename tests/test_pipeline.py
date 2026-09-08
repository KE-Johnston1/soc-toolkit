from pathlib import Path
import unittest

from soc_toolkit.pipeline import PipelineInput, run_pipeline


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.log = str(Path(__file__).parents[1] / "logs" / "pipeline-auth.log")

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
        self.assertIn("authentication log", result.correlated_sources)

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
