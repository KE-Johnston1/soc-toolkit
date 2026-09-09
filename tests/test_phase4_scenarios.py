import unittest
from pathlib import Path

from soc_toolkit.scenario_validation import validate_scenario


class ScenarioRegressionTests(unittest.TestCase):
    def test_all_phase3_scenarios_have_valid_structure(self):
        root = Path(__file__).parents[1] / "cases"
        scenario_ids = ("CASE-PHISH-001", "CASE-NET-001", "CASE-INSIDER-001")
        for case_id in scenario_ids:
            with self.subTest(case_id=case_id):
                self.assertEqual(validate_scenario(root / case_id / "scenario.json"), [])


if __name__ == "__main__":
    unittest.main()
