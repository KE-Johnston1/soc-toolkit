import tempfile
import unittest
from pathlib import Path

from soc_toolkit.reporting import AnalystReport, ReportEvidence, render_markdown
from soc_toolkit.scenario_cases import load_scenario_case


class Phase3Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parents[1]

    def test_scenario_packs_are_reproducible_and_complete(self):
        cases = [
            self.root / "cases" / "CASE-PHISH-001" / "scenario.json",
            self.root / "cases" / "CASE-NET-001" / "scenario.json",
            self.root / "cases" / "CASE-INSIDER-001" / "scenario.json",
        ]
        loaded = [load_scenario_case(path) for path in cases]
        self.assertEqual({case.case_id for case in loaded}, {"CASE-PHISH-001", "CASE-NET-001", "CASE-INSIDER-001"})
        for case in loaded:
            self.assertTrue(case.evidence)
            self.assertTrue(case.data["hypotheses"])
            self.assertTrue(case.data["lessons_learned"])

    def test_report_renderer_preserves_evidence_provenance(self):
        report = AnalystReport(
            case_id="CASE-TEST-001",
            title="Test report",
            scenario="test",
            assessment="Requires Investigation",
            confidence="Medium",
            executive_summary="A synthetic investigation remains open.",
            key_observations=("An event was observed.",),
            evidence=(ReportEvidence("E-1", "test.log", "Observed event", "observed", "High", "neutral"),),
            hypotheses=("Legitimate activity", "Security-related activity"),
            evidence_gaps=("ownership is unknown",),
            risk_summary="Risk is provisional.",
            escalation_summary="SOC Investigation.",
            response_summary="Investigate.",
            closure_status="Not ready.",
            lessons_learned=("Verify context before closure.",),
        )
        rendered = render_markdown(report)
        self.assertIn("## Evidence matrix", rendered)
        self.assertIn("observed", rendered)
        self.assertIn("ownership is unknown", rendered)
        self.assertIn("Competing hypotheses", rendered)
        self.assertIn("does not establish compromise", rendered)


if __name__ == "__main__":
    unittest.main()
