import unittest

from soc_toolkit.scenario_context import ScenarioContext, required_evidence, scenario_gaps


class ScenarioContextTests(unittest.TestCase):
    def test_supported_scenarios_have_explicit_evidence_requirements(self):
        for scenario in (
            "Credential Attack",
            "Malware",
            "Command and Control",
            "Exfiltration",
            "Phishing",
            "Impersonation",
            "Social Engineering",
            "Insider Threat",
            "AI-Assisted Attack",
        ):
            context = ScenarioContext(scenario_type=scenario, rationale=f"Testing {scenario} scenario context.")
            self.assertTrue(required_evidence(context))

    def test_c2_gaps_are_explicit(self):
        context = ScenarioContext(scenario_type="Command and Control", indicator_present=True, rationale="Unusual periodic outbound traffic requires validation.")
        gaps = scenario_gaps(context, {"network evidence"})
        self.assertIn("destination context", gaps)
        self.assertIn("endpoint/process correlation", gaps)

    def test_established_scenario_requires_indicator(self):
        with self.assertRaises(ValueError):
            ScenarioContext(scenario_type="Malware", classification_established=True, rationale="Classification requires an underlying indicator.")


if __name__ == "__main__":
    unittest.main()
