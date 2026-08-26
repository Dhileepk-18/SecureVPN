import threading
import time

class MetricsCollector:
    """Thread-safe real-time telemetry collector for SecureVPN server."""
    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = time.time()
        
        # Telemetry Counters
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.total_packets_sent = 0
        self.total_packets_received = 0
        
        self.total_connections = 0
        self.active_connections = 0
        self.successful_logins = 0
        self.failed_logins = 0
        self.key_rotations = 0
        self.replayed_packets_dropped = 0

    def record_connection_start(self):
        with self._lock:
            self.total_connections += 1
            self.active_connections += 1

    def record_connection_end(self):
        with self._lock:
            self.active_connections = max(0, self.active_connections - 1)

    def record_bytes_sent(self, count: int):
        with self._lock:
            self.total_bytes_sent += count
            self.total_packets_sent += 1

    def record_bytes_received(self, count: int):
        with self._lock:
            self.total_bytes_received += count
            self.total_packets_received += 1

    def record_login_success(self):
        with self._lock:
            self.successful_logins += 1

    def record_login_failure(self):
        with self._lock:
            self.failed_logins += 1

    def record_key_rotation(self):
        with self._lock:
            self.key_rotations += 1

    def record_replay_drop(self):
        with self._lock:
            self.replayed_packets_dropped += 1

    def get_summary(self) -> dict:
        """Returns a snapshot of server telemetry."""
        with self._lock:
            uptime = max(time.time() - self.start_time, 0.000001)
            total_mb_sent = self.total_bytes_sent / (1024 * 1024)
            total_mb_recvd = self.total_bytes_received / (1024 * 1024)
            
            return {
                "uptime_seconds": round(uptime, 2),
                "active_connections": self.active_connections,
                "total_connections": self.total_connections,
                "successful_logins": self.successful_logins,
                "failed_logins": self.failed_logins,
                "key_rotations": self.key_rotations,
                "replayed_packets_dropped": self.replayed_packets_dropped,
                "total_mb_sent": round(total_mb_sent, 2),
                "total_mb_received": round(total_mb_recvd, 2),
                "total_packets_processed": self.total_packets_sent + self.total_packets_received,
            }
