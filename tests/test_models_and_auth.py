import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from detections.authentication import detect_repeated_auth_failures
from parsers.auth_parser import parse_auth_log
from soc_toolkit.models import LogEvent


SAMPLE_AUTH = (
    "Sep 28 14:02:01 sshd[1234]: Failed password for invalid user admin from 192.168.1.101 port 22\n"
    "Sep 28 14:02:03 sshd[1234]: Failed password for invalid user admin from 192.168.1.101 port 22\n"
)


class TestLogEvent(unittest.TestCase):
    def test_rejects_naive_timestamp(self):
        with self.assertRaises(ValueError):
            LogEvent(
                timestamp=datetime(2026, 9, 28, 14, 2, 1),
                source_ip="192.168.1.101",
                destination_ip=None,
                source_port=22,
                destination_port=22,
                protocol="TCP",
                event_type="authentication_failure",
                account="admin",
                action="failure",
                message="test",
                evidence_source="test",
                raw_line="test",
            )

    def test_rejects_invalid_ip_and_port(self):
        with self.assertRaises(ValueError):
            LogEvent(None, "999.999.999.999", None, 22, 22, "tcp", "x", None, None, "test", "test", "test")
        with self.assertRaises(ValueError):
            LogEvent(None, "192.168.1.1", None, 22, 70000, "tcp", "x", None, None, "test", "test", "test")


class TestAuthParser(unittest.TestCase):
    def test_parses_failures_without_inventing_timestamp(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(SAMPLE_AUTH, encoding="utf-8")
            events = parse_auth_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source_ip, "192.168.1.101")
        self.assertEqual(events[0].destination_port, 22)
        self.assertEqual(events[0].account, "admin")
        self.assertIsNone(events[0].timestamp)
        self.assertEqual(events[0].metadata["invalid_user"], True)

    def test_parses_trustworthy_timestamp_when_context_is_supplied(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(SAMPLE_AUTH, encoding="utf-8")
            events = parse_auth_log(path, year=2026, tz=timezone.utc)

        self.assertEqual(events[0].timestamp, datetime(2026, 9, 28, 14, 2, 1, tzinfo=timezone.utc))


class TestAuthenticationDetection(unittest.TestCase):
    def _events(self, timestamped: bool = True):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            lines = [
                f"Sep 28 14:02:0{i} sshd[1234]: Failed password for invalid user admin from 192.168.1.101 port 22\n"
                for i in range(1, 6)
            ]
            path.write_text("".join(lines), encoding="utf-8")
            return parse_auth_log(path, year=2026, tz=timezone.utc) if timestamped else parse_auth_log(path)

    def test_threshold_and_window(self):
        results = detect_repeated_auth_failures(self._events(), threshold=5, window=timedelta(minutes=5))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].confidence, "Medium")
        self.assertEqual(results[0].assessment, "Requires Investigation")

    def test_count_without_trustworthy_time_is_low_confidence(self):
        results = detect_repeated_auth_failures(self._events(timestamped=False), threshold=5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].confidence, "Low")
        self.assertIn("trustworthy timestamps", results[0].evidence_gaps[0])

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            detect_repeated_auth_failures([], threshold=0)


if __name__ == "__main__":
    unittest.main()
