"""Regression checks for the portable detection-engineering catalogue."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DetectionEngineeringCatalogueTests(unittest.TestCase):
    def test_authentication_catalogue_contains_required_formats(self) -> None:
        required = [
            ROOT / "detections" / "authentication.py",
            ROOT / "detections" / "sigma" / "ssh_auth_failures.yml",
            ROOT / "detections" / "sigma" / "ssh_repeated_auth_failures.yml",
            ROOT / "detections" / "sigma" / "ssh_password_spray_correlation.yml",
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "ssh-password-spray.kql",
            ROOT / "detections" / "queries" / "splunk" / "ssh-password-spray.spl",
            ROOT / "docs" / "detection-engineering.md",
        ]
        for path in required:
            self.assertTrue(path.is_file(), f"missing detection-engineering artefact: {path}")

    def test_portable_queries_share_rule_and_attack_mapping(self) -> None:
        paths = [
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "ssh-password-spray.kql",
            ROOT / "detections" / "queries" / "splunk" / "ssh-password-spray.spl",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertIn("AUTH-REPEAT-001", text)
            self.assertIn("T1110.003", text)
            self.assertIn("Requires Investigation", text)

    def test_sigma_rules_document_false_positive_and_attack_context(self) -> None:
        sigma_dir = ROOT / "detections" / "sigma"
        for path in sigma_dir.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("falsepositives:", text)
            self.assertIn("tags:", text)
            self.assertIn("attack.t1110", text)


if __name__ == "__main__":
    unittest.main()
