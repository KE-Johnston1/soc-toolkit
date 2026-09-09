import json
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.case_metrics import summarise_cases
from soc_toolkit.quality import DetectionCheck, evaluate_detection_quality
from soc_toolkit.scenario_validation import validate_scenario


class Phase4QualityTests(unittest.TestCase):
    def test_detection_quality_reports_false_positive_and_recall(self):
        result = evaluate_detection_quality([
            DetectionCheck("A", "R1", True, True, "expected signal"),
            DetectionCheck("B", "R1", False, True, "known benign admin activity"),
            DetectionCheck("C", "R1", True, False, "signal outside configured threshold"),
            DetectionCheck("D", "R1", False, False, "benign baseline"),
        ])
        self.assertEqual((result.true_positive, result.false_positive, result.true_negative, result.false_negative), (1, 1, 1, 1))
        self.assertEqual(result.precision, 0.5)
        self.assertEqual(result.recall, 0.5)
        self.assertTrue(result.tuning_notes)

    def test_empty_quality_input_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_detection_quality([])

    def test_scenario_validation_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.json"
            path.write_text(json.dumps({"case_id": "X"}), encoding="utf-8")
            errors = validate_scenario(path)
            self.assertIn("missing required field: assessment", errors)

    def test_scenario_validation_accepts_required_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.json"
            data = {key: [] for key in ("hypotheses", "evidence", "lessons_learned")}
            data.update({key: "value" for key in ("case_id", "title", "scenario", "assessment", "confidence", "risk", "escalation", "response", "closure")})
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(validate_scenario(path), [])

    def test_case_metrics_identify_unresolved_cases(self):
        result = summarise_cases([
            {"assessment": "Requires Investigation", "escalation": "Tier 2", "response": "Investigate", "closure_ready": False},
            {"assessment": "Insufficient Evidence", "escalation": "Monitor", "response": "Investigate", "closure_ready": False},
            {"assessment": "Expected", "escalation": "No Escalation", "response": "Close", "closure_ready": True},
        ])
        self.assertEqual(result.total_cases, 3)
        self.assertEqual(result.unresolved_cases, 2)
        self.assertEqual(result.closure_ready, 1)


if __name__ == "__main__":
    unittest.main()
