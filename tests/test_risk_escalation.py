import unittest

from soc_toolkit.escalation import EscalationInput, recommend_escalation
from soc_toolkit.risk import RiskInput, assess_risk

class RiskTests(unittest.TestCase):
    def test_unknown_context_stays_unknown(self):
        result = assess_risk(RiskInput())
        self.assertEqual(result.overall_risk, "Unknown")
        self.assertTrue(result.evidence_gaps)

    def test_high_context_produces_high_risk(self):
        result = assess_risk(RiskInput(asset_criticality="High", account_privilege="High", data_sensitivity="High", likelihood="High", business_impact="High", confidence="Medium"))
        self.assertEqual(result.overall_risk, "High")
        self.assertIn("financial impact is unknown", result.evidence_gaps)

class EscalationTests(unittest.TestCase):
    def test_privileged_account_recommends_tier_two(self):
        result = recommend_escalation(EscalationInput("Requires Investigation", "Medium", privileged_account=True))
        self.assertEqual(result.level, "Tier 2")
        self.assertIn("privileged account involved", result.triggers)

    def test_malware_recommends_incident_response(self):
        result = recommend_escalation(EscalationInput("Requires Investigation", "High", malware_evidence=True, business_impact="High"))
        self.assertEqual(result.level, "Incident Response")

    def test_sensitive_data_refers_to_privacy(self):
        result = recommend_escalation(EscalationInput("Requires Investigation", "Medium", sensitive_data_involved=True))
        self.assertEqual(result.level, "Management/Legal/Privacy")

    def test_insufficient_evidence_does_not_jump_to_incident_response(self):
        result = recommend_escalation(EscalationInput("Insufficient Evidence", "Low"))
        self.assertEqual(result.level, "Monitor")

if __name__ == "__main__":
    unittest.main()
