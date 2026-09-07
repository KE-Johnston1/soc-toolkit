import unittest
from datetime import datetime, timezone

from soc_toolkit.case_management import CaseRecord, transition_case
from soc_toolkit.response import ResponseInput, recommend_response


class ResponseTests(unittest.TestCase):
    def test_insufficient_evidence_requires_investigation(self):
        result = recommend_response(ResponseInput("Insufficient Evidence", "Low", evidence_gaps=("ownership is unknown",)))
        self.assertEqual(result.action, "Investigate")

    def test_incident_response_requires_authorized_safe_containment(self):
        result = recommend_response(ResponseInput("Security Concern", "High", escalation_level="Incident Response"))
        self.assertEqual(result.action, "Escalate")
        self.assertTrue(result.authorization_required)

    def test_authorized_safe_containment_is_selected(self):
        result = recommend_response(ResponseInput("Security Concern", "High", escalation_level="Incident Response", containment_authorized=True, containment_safe=True))
        self.assertEqual(result.action, "Contain")

    def test_closure_requires_expected_and_no_gaps(self):
        result = recommend_response(ResponseInput("Expected", "High", closure_criteria_met=True, closure_rationale="Verified against baseline and playbook."))
        self.assertEqual(result.action, "Close")


class CaseTests(unittest.TestCase):
    def make_case(self):
        return CaseRecord("CASE-001", "ALERT-001", datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc))

    def test_invalid_transition_is_rejected(self):
        with self.assertRaises(ValueError):
            transition_case(self.make_case(), "Contained", actor_role="Analyst", rationale="Not supported directly from Open.")

    def test_case_cannot_close_with_unresolved_gaps(self):
        case = self.make_case()
        case.assessment = "Expected"
        case.evidence_gaps = ["network evidence is not reviewed"]
        case.closure_rationale = "Attempted closure."
        with self.assertRaises(ValueError):
            transition_case(case, "Closed", actor_role="Analyst", rationale="Evidence is incomplete.")

    def test_case_closes_with_required_criteria(self):
        case = self.make_case()
        case.assessment = "Expected"
        case.closure_rationale = "Ownership, authorization, baseline and supporting evidence verified."
        transition_case(case, "Closed", actor_role="Analyst", rationale="Closure criteria are satisfied.", confidence="High")
        self.assertEqual(case.status, "Closed")
        self.assertEqual(len(case.decision_trail), 1)


if __name__ == "__main__":
    unittest.main()
