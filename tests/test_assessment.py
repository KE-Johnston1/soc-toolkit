import unittest

from soc_toolkit.assessment import AssessmentInput, EvidenceItem, assess_detection


class TestAnalystAssessment(unittest.TestCase):
    def _complete(self, **overrides):
        values = {
            "detection_present": True,
            "ownership_verified": True,
            "authorization_verified": True,
            "expected_activity_verified": True,
            "timing_verified": True,
            "network_reviewed": True,
            "endpoint_reviewed": True,
            "change_or_testing_checked": True,
            "post_auth_reviewed": True,
        }
        values.update(overrides)
        return AssessmentInput(**values)

    def test_missing_ownership_or_authorization_is_insufficient(self):
        result = assess_detection(
            self._complete(ownership_verified=False, authorization_verified=False)
        )
        self.assertEqual(result.assessment, "Insufficient Evidence")
        self.assertEqual(result.confidence, "Low")
        self.assertIn("ownership", result.evidence_gaps[0])
        self.assertIn("authorization", result.evidence_gaps[1])

    def test_authorized_activity_with_missing_change_context_requires_investigation(self):
        result = assess_detection(self._complete(change_or_testing_checked=False))
        self.assertEqual(result.assessment, "Requires Investigation")
        self.assertEqual(result.confidence, "Medium")
        self.assertIn("change", " ".join(result.evidence_gaps))

    def test_complete_expected_activity_can_close(self):
        result = assess_detection(
            self._complete(
                evidence=(
                    EvidenceItem(
                        source="synthetic change record",
                        observation="SSH administration matched an approved maintenance window",
                        confidence="High",
                        relationship="corroborating",
                    ),
                )
            )
        )
        self.assertEqual(result.assessment, "Expected")
        self.assertEqual(result.confidence, "High")
        self.assertEqual(result.evidence_gaps, ())

    def test_contradictory_evidence_prevents_expected_closure(self):
        result = assess_detection(self._complete(contradictory_evidence=True))
        self.assertEqual(result.assessment, "Requires Investigation")
        self.assertIn("contradictions", " ".join(result.evidence_gaps))
        self.assertIn("Resolve contradictions", result.recommended_action)

    def test_privileged_success_without_post_auth_review_requires_investigation(self):
        result = assess_detection(
            self._complete(privileged_account=True, post_auth_reviewed=False)
        )
        self.assertEqual(result.assessment, "Requires Investigation")
        self.assertIn("privileged", " ".join(result.evidence_gaps))

    def test_evidence_item_rejects_blank_source(self):
        with self.assertRaises(ValueError):
            EvidenceItem(source=" ", observation="Observed event", confidence="Medium")


if __name__ == "__main__":
    unittest.main()
