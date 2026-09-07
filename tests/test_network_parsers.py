import tempfile
import unittest
from pathlib import Path

from parsers.firewall_parser import parse_firewall_log
from parsers.web_parser import parse_web_log


class TestNetworkParsers(unittest.TestCase):
    def _write(self, content: str) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with handle:
            handle.write(content)
        return Path(handle.name)

    def test_firewall_parser_returns_structured_events(self):
        path = self._write(
            "Sep 28 14:05:10 firewall: Blocked connection from 203.0.113.45 to port 22\n"
        )
        try:
            events = parse_firewall_log(path)
        finally:
            path.unlink()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_ip, "203.0.113.45")
        self.assertEqual(events[0].destination_port, 22)
        self.assertEqual(events[0].action, "blocked")
        self.assertIsNone(events[0].timestamp)
        self.assertEqual(events[0].metadata["syslog_timestamp"], "Sep 28 14:05:10")

    def test_web_parser_preserves_request_path(self):
        path = self._write(
            "Sep 28 14:10:00 webserver: GET /admin from 198.51.100.23\n"
        )
        try:
            events = parse_web_log(path)
        finally:
            path.unlink()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "web_request")
        self.assertEqual(events[0].source_ip, "198.51.100.23")
        self.assertEqual(events[0].action, "GET")
        self.assertEqual(events[0].metadata["request_path"], "/admin")
        self.assertIsNone(events[0].protocol)
        self.assertIsNone(events[0].destination_port)

    def test_malformed_records_are_ignored(self):
        path = self._write("not a valid firewall record\n")
        try:
            self.assertEqual(parse_firewall_log(path), [])
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
