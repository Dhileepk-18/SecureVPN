import time
import os
from monitoring.metrics import MetricsCollector

class TelemetryDashboard:
    """Renders formatted ASCII telemetry dashboard for terminal display."""
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector

    def render_snapshot(self) -> str:
        summary = self.metrics.get_summary()
        
        banner = "=" * 80 + "\n"
        title = " " * 20 + "SECUREVPN REAL-TIME TELEMETRY DASHBOARD\n"
        banner_end = "=" * 80 + "\n"

        status_sec = (
            f" Server Status       : ACTIVE\n"
            f" Uptime              : {summary['uptime_seconds']} seconds\n"
            f" Active Connections  : {summary['active_connections']}\n"
            f" Total Connections   : {summary['total_connections']}\n"
        )
        divider = "-" * 80 + "\n"

        network_sec = (
            f" NETWORK THROUGHPUT & PACKET COUNTERS:\n"
            f"   MB Received       : {summary['total_mb_received']} MB\n"
            f"   MB Sent           : {summary['total_mb_sent']} MB\n"
            f"   Total Packets     : {summary['total_packets_processed']} packets\n"
        )

        security_sec = (
            f" SECURITY AUDIT COUNTERS:\n"
            f"   Successful Logins : {summary['successful_logins']}\n"
            f"   Failed Logins     : {summary['failed_logins']}\n"
            f"   Key Rotations     : {summary['key_rotations']}\n"
            f"   Replayed Dropped  : {summary['replayed_packets_dropped']}\n"
        )

        return banner + title + banner_end + status_sec + divider + network_sec + divider + security_sec + banner_end

    def start_cli_loop(self, refresh_interval: float = 2.0):
        """Runs a live updating dashboard terminal screen."""
        try:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                print(self.render_snapshot())
                time.sleep(refresh_interval)
        except KeyboardInterrupt:
            pass
