"""Regression checks for the portable detection-engineering catalogue."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DetectionEngineeringCatalogueTests(unittest.TestCase):
    def test_catalogue_contains_required_formats(self) -> None:
        required = [
            ROOT / "detections" / "authentication.py",
            ROOT / "detections" / "sigma" / "ssh_auth_failures.yml",
            ROOT / "detections" / "sigma" / "ssh_repeated_auth_failures.yml",
            ROOT / "detections" / "sigma" / "ssh_password_spray_correlation.yml",
            ROOT / "detections" / "sigma" / "suspicious_powershell.yml",
            ROOT / "detections" / "sigma" / "privileged_login_context.yml",
            ROOT / "detections" / "sigma" / "network_beaconing.yml",
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "ssh-password-spray.kql",
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "suspicious-powershell.kql",
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "privileged-login-context.kql",
            ROOT / "detections" / "queries" / "microsoft-sentinel" / "network-beaconing.kql",
            ROOT / "detections" / "queries" / "splunk" / "ssh-password-spray.spl",
            ROOT / "detections" / "queries" / "splunk" / "suspicious-powershell.spl",
            ROOT / "detections" / "queries" / "splunk" / "privileged-login-context.spl",
            ROOT / "detections" / "queries" / "splunk" / "network-beaconing.spl",
            ROOT / "docs" / "detection-engineering.md",
        ]
        for path in required:
            self.assertTrue(path.is_file(), f"missing detection-engineering artefact: {path}")

    def test_portable_queries_have_rule_and_attack_mapping(self) -> None:
        expected = {
            "ssh-password-spray.kql": ("AUTH-REPEAT-001", "T1110.003"),
            "ssh-password-spray.spl": ("AUTH-REPEAT-001", "T1110.003"),
            "suspicious-powershell.kql": ("SOC-EXEC-001", "T1059.001"),
            "suspicious-powershell.spl": ("SOC-EXEC-001", "T1059.001"),
            "privileged-login-context.kql": ("SOC-ID-001", "T1078"),
            "privileged-login-context.spl": ("SOC-ID-001", "T1078"),
            "network-beaconing.kql": ("SOC-NET-001", "T1071"),
            "network-beaconing.spl": ("SOC-NET-001", "T1071"),
        }
        for directory in ("microsoft-sentinel", "splunk"):
            query_dir = ROOT / "detections" / "queries" / directory
            for filename, (rule_id, attack_id) in expected.items():
                if filename not in {path.name for path in query_dir.iterdir()}:
                    continue
                text = (query_dir / filename).read_text(encoding="utf-8")
                self.assertIn(rule_id, text)
                self.assertIn(attack_id, text)
                self.assertIn("Requires Investigation", text)

    def test_sigma_rules_document_false_positive_and_attack_context(self) -> None:
        sigma_dir = ROOT / "detections" / "sigma"
        for path in sigma_dir.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("falsepositives:", text)
            self.assertIn("tags:", text)
            self.assertIn("attack.", text)


if __name__ == "__main__":
    unittest.main()
