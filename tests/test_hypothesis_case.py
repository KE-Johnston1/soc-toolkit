import unittest
from pathlib import Path
from datetime import timedelta

from soc_toolkit.case_loader import load_case_pack
from soc_toolkit.correlation import correlate_events
from soc_toolkit.hypothesis_case import build_case_hypotheses


class CaseHypothesisTests(unittest.TestCase):
    def test_multisource_case_produces_competing_hypotheses(self):
        case_path = Path(__file__).parents[1] / "cases" / "CASE-MULTI-001"
        pack = load_case_pack(case_path)
        correlations = correlate_events(pack.events, window=timedelta(minutes=5))
        hypotheses = build_case_hypotheses(pack.events, correlations)

        self.assertEqual(len(hypotheses), 5)
        self.assertEqual(hypotheses[0].status, "Challenged")
        self.assertEqual(hypotheses[1].status, "Supported")
        self.assertEqual(hypotheses[2].status, "Supported")
        self.assertEqual(hypotheses[3].status, "Supported")
        self.assertEqual(hypotheses[4].status, "Open")
        self.assertIn("not proof", hypotheses[1].rationale)
        self.assertIn("authorization", hypotheses[0].evidence[0].observation)


if __name__ == "__main__":
    unittest.main()
