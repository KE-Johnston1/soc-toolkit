import unittest
from datetime import datetime, timezone

from soc_toolkit.correlation import correlate_events
from soc_toolkit.models import LogEvent


class CorrelationTests(unittest.TestCase):
    def event(self, source, event_type, second, timestamp=True):
        return LogEvent(
            timestamp=datetime(2026, 9, 28, 14, 5, second, tzinfo=timezone.utc) if timestamp else None,
            source_ip="203.0.113.45",
            destination_ip=None,
            source_port=None,
            destination_port=22,
            protocol="tcp",
            event_type=event_type,
            account=None,
            action="blocked",
            message=f"synthetic {event_type}",
            evidence_source=source,
            raw_line=f"synthetic {event_type}",
        )

    def test_multi_source_events_with_complete_timestamps_are_correlated(self):
        result = correlate_events([
            self.event("auth.log", "authentication_failure", 1),
            self.event("firewall.log", "network_connection", 3),
        ])[0]
        self.assertEqual(result.assessment, "Correlated")
        self.assertEqual(result.confidence, "Medium")
        self.assertTrue(result.temporal_correlation)

    def test_multi_source_events_without_timestamps_are_low_confidence(self):
        result = correlate_events([
            self.event("auth.log", "authentication_failure", 1, False),
            self.event("firewall.log", "network_connection", 3, False),
        ])[0]
        self.assertEqual(result.assessment, "Correlated")
        self.assertEqual(result.confidence, "Low")
        self.assertFalse(result.temporal_correlation)

    def test_single_source_event_is_only_observed(self):
        result = correlate_events([self.event("auth.log", "authentication_failure", 1)])[0]
        self.assertEqual(result.assessment, "Observed")
        self.assertEqual(result.confidence, "Medium")


if __name__ == "__main__":
    unittest.main()
