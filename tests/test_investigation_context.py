import unittest

from soc_toolkit.investigation_context import (
    AttributionContext,
    ImpactContext,
    LegalPrivacyContext,
    VulnerabilityContext,
    assess_vulnerability,
)


class InvestigationContextTests(unittest.TestCase):
    def test_unknown_vulnerability_stays_unknown(self):
        relevance, gaps = assess_vulnerability(VulnerabilityContext())
        self.assertEqual(relevance, "Unknown")
        self.assertIn("affected product is unknown", gaps)
        self.assertIn("CVE applicability is unknown", gaps)

    def test_applicable_cve_does_not_equal_exploitation(self):
        relevance, gaps = assess_vulnerability(
            VulnerabilityContext(
                product="Example Server",
                version="1.2.3",
                version_confirmed=True,
                cve_id="CVE-2026-12345",
                vulnerability_applicable=True,
                exploitation_evidence=False,
                cvss_severity="High",
            )
        )
        self.assertEqual(relevance, "Potentially Relevant - Exploitation Not Established")
        self.assertEqual(gaps, ())

    def test_exploitation_requires_applicability(self):
        with self.assertRaises(ValueError):
            VulnerabilityContext(exploitation_evidence=True)

    def test_financial_value_requires_basis(self):
        with self.assertRaises(ValueError):
            ImpactContext(financial_value=1000)

    def test_legal_referral_is_workflow_context(self):
        context = LegalPrivacyContext(
            consideration_present=True,
            data_category="Unknown",
            jurisdiction="Unknown",
            referral_required=True,
        )
        self.assertTrue(context.referral_required)
        self.assertFalse(context.evidence_established)

    def test_attribution_preserves_proxy_uncertainty(self):
        context = AttributionContext(
            source_ip="192.0.2.10",
            source_identity="Unknown",
            shared_or_proxied_source_possible=True,
            confidence="Low",
            rationale="A source IP identifies a network endpoint, not necessarily the individual actor.",
        )
        self.assertTrue(context.shared_or_proxied_source_possible)
        self.assertEqual(context.confidence, "Low")


if __name__ == "__main__":
    unittest.main()
