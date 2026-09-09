from datetime import datetime, timezone
import unittest

from soc_toolkit.evidence import EvidenceRecord, summarise_evidence, strongest_confidence
from soc_toolkit.pipeline import PipelineInput, run_pipeline
from pathlib import Path


class EvidenceTests(unittest.TestCase):
    def test_evidence_requires_timezone_aware_timestamp(self):
        with self.assertRaises(ValueError):
            EvidenceRecord(
                evidence_id="E1",
                source="auth.log",
                observation="authentication failure",
                evidence_type="observed",
                confidence="Medium",
                observed_at=datetime(2026, 9, 8, 14, 0),
            )

    def test_summary_preserves_provenance_categories(self):
        records = (
            EvidenceRecord("E1", "auth.log", "failure", "observed", "High", observed_at=datetime(2026, 9, 8, 14, 0, tzinfo=timezone.utc)),
            EvidenceRecord("E2", "correlation", "same source", "correlated", "Medium"),
            EvidenceRecord("E3", "analyst", "possible explanation", "hypothesis", "Low"),
            EvidenceRecord("E4", "analyst", "possible inference", "inferred", "Low"),
            EvidenceRecord("E5", "case", "not established", "unknown", "Low"),
        )
        summary = summarise_evidence(records)
        self.assertEqual(summary.total, 5)
        self.assertEqual(summary.observed, 1)
        self.assertEqual(summary.correlated, 1)
        self.assertEqual(summary.inferred, 1)
        self.assertEqual(summary.hypothesis, 1)
        self.assertEqual(summary.unknown, 1)
        self.assertEqual(summary.direct_sources, ("auth.log",))
        self.assertEqual(strongest_confidence(records), "High")

    def test_phase2_pipeline_exposes_typed_evidence(self):
        case = Path(__file__).parents[1] / "cases" / "CASE-MULTI-001"
        result = run_pipeline(
            PipelineInput(case_id="CASE-MULTI-001", alert_id="ALERT-AUTH-001", case_path=str(case))
        )
        self.assertEqual(result.evidence_summary.total, len(result.events) + 1)
        self.assertEqual(result.evidence_summary.observed, len(result.events))
        self.assertEqual(result.evidence_summary.correlated, 1)
        self.assertEqual(result.evidence_summary.direct_sources, tuple(sorted(result.correlated_sources)))
        self.assertTrue(all(item.evidence_type == "observed" for item in result.evidence_records[:len(result.events)]))
        self.assertIn("does not establish attribution", result.evidence_records[-1].notes)


if __name__ == "__main__":
    unittest.main()
