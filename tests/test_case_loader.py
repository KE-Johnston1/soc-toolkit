from pathlib import Path
import unittest
from datetime import timedelta

from soc_toolkit.case_loader import load_case_pack
from soc_toolkit.correlation import correlate_events


class CasePackTests(unittest.TestCase):
    def setUp(self):
        self.case = Path(__file__).parents[1] / "cases" / "CASE-MULTI-001"

    def test_loads_auth_firewall_and_web_evidence(self):
        pack = load_case_pack(self.case)
        sources = {event.evidence_source for event in pack.events}
        self.assertEqual(sources, {str(self.case / "auth.log"), str(self.case / "firewall.log"), str(self.case / "web.log")})
        self.assertEqual(pack.case_id, "CASE-MULTI-001")
        self.assertEqual(len(pack.events), 9)

    def test_correlates_same_source_across_multiple_evidence_types(self):
        pack = load_case_pack(self.case)
        results = correlate_events(pack.events, window=timedelta(minutes=5))
        match = next(result for result in results if result.source_ip == "192.168.1.101")
        self.assertEqual(match.assessment, "Correlated")
        self.assertEqual(match.confidence, "Medium")
        self.assertTrue(match.temporal_correlation)
        self.assertEqual(len(match.evidence_sources), 3)
        self.assertIn("firewall_block", match.event_types)
        self.assertIn("web_request", match.event_types)
        self.assertIn("authentication_failure", match.event_types)
        self.assertIn("does not establish attribution", match.rationale)


if __name__ == "__main__":
    unittest.main()
