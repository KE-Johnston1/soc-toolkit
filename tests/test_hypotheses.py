import unittest

from soc_toolkit.hypotheses import HypothesisEvidence, evaluate_hypothesis


class HypothesisTests(unittest.TestCase):
    def test_supporting_evidence_does_not_claim_certainty(self):
        result = evaluate_hypothesis(
            "H1",
            "Credential attack",
            (HypothesisEvidence("E1", "Repeated SSH failures from one source", "supports", "Medium"),),
        )
        self.assertEqual(result.status, "Supported")
        self.assertEqual(result.confidence, "Medium")
        self.assertIn("not proof", result.rationale)

    def test_supporting_and_challenging_evidence_remains_unresolved(self):
        result = evaluate_hypothesis(
            "H2",
            "Legitimate administration",
            (
                HypothesisEvidence("E1", "Known administration source", "supports", "Medium"),
                HypothesisEvidence("E2", "Repeated failures followed by success", "challenges", "Medium"),
            ),
        )
        self.assertEqual(result.status, "Unresolved")
        self.assertEqual(result.confidence, "Medium")

    def test_no_evidence_keeps_hypothesis_open(self):
        result = evaluate_hypothesis("H3", "Unknown activity", ())
        self.assertEqual(result.status, "Open")
        self.assertEqual(result.confidence, "Low")


if __name__ == "__main__":
    unittest.main()
