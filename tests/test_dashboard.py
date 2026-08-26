import unittest
from monitoring.metrics import MetricsCollector
from monitoring.dashboard import TelemetryDashboard

class TestTelemetryDashboard(unittest.TestCase):

    def test_dashboard_rendering(self):
        collector = MetricsCollector()
        collector.record_connection_start()
        collector.record_login_success()

        dash = TelemetryDashboard(collector)
        rendered_text = dash.render_snapshot()

        self.assertIn("SECUREVPN REAL-TIME TELEMETRY DASHBOARD", rendered_text)
        self.assertIn("Active Connections  : 1", rendered_text)
        self.assertIn("Successful Logins : 1", rendered_text)

if __name__ == '__main__':
    unittest.main()
