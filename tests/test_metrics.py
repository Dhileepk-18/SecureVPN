import unittest
import time
from monitoring.metrics import MetricsCollector

class TestMetricsCollector(unittest.TestCase):

    def test_metrics_counters(self):
        collector = MetricsCollector()
        time.sleep(0.01)  # Brief delay to ensure non-zero uptime

        collector.record_connection_start()
        collector.record_bytes_sent(1024)
        collector.record_bytes_received(2048)
        collector.record_login_success()
        collector.record_key_rotation()

        summary = collector.get_summary()

        self.assertEqual(summary["active_connections"], 1)
        self.assertEqual(summary["total_connections"], 1)
        self.assertEqual(summary["successful_logins"], 1)
        self.assertEqual(summary["key_rotations"], 1)
        self.assertGreaterEqual(summary["uptime_seconds"], 0)

    def test_connection_cleanup_metrics(self):
        collector = MetricsCollector()

        collector.record_connection_start()
        self.assertEqual(collector.active_connections, 1)

        collector.record_connection_end()
        self.assertEqual(collector.active_connections, 0)

if __name__ == '__main__':
    unittest.main()
