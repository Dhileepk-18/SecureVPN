import os
import time
from crypto.key_derivation import rotate_traffic_key

class ReplayWindow:
    def __init__(self, window_size: int = 64):
        self.window_size = window_size
        self.last_seq = 0
        self.bitmap = 0

    def validate_and_update(self, seq: int) -> bool:
        if seq <= 0:
            return False

        if seq > self.last_seq:
            diff = seq - self.last_seq
            if diff < self.window_size:
                self.bitmap = (self.bitmap << diff) | 1
            else:
                self.bitmap = 1
            self.last_seq = seq
            return True

        diff = self.last_seq - seq
        if diff >= self.window_size:
            return False

        if (self.bitmap & (1 << diff)) != 0:
            return False

        self.bitmap |= (1 << diff)
        return True

class Session:
    def __init__(self, peer_addr, c2s_key: bytes, s2s_key: bytes, username: str = None):
        self.session_id = os.urandom(16).hex()
        self.peer_addr = peer_addr
        self.username = username
        
        # Epoch & Key Management
        self.epoch = 0
        self.c2s_keys = {0: c2s_key}
        self.s2s_keys = {0: s2s_key}
        self.bytes_sent = 0
        
        self.created_at = time.time()
        self.last_activity_time = time.time()
        
        self.send_seq = 0
        self.replay_window = ReplayWindow()

    @property
    def current_c2s_key(self) -> bytes:
        return self.c2s_keys[self.epoch]

    @property
    def current_s2s_key(self) -> bytes:
        return self.s2s_keys[self.epoch]

    def rotate_session_keys(self):
        """Rotates c2s and s2s keys to the next Epoch."""
        next_epoch = self.epoch + 1
        new_c2s = rotate_traffic_key(self.current_c2s_key, next_epoch, b"c2s-rotation")
        new_s2s = rotate_traffic_key(self.current_s2s_key, next_epoch, b"s2s-rotation")

        self.c2s_keys[next_epoch] = new_c2s
        self.s2s_keys[next_epoch] = new_s2s
        self.epoch = next_epoch
        self.bytes_sent = 0  # Reset byte counter

    def touch_activity(self, bytes_count: int = 0):
        self.last_activity_time = time.time()
        self.bytes_sent += bytes_count

    def should_rotate_keys(self, threshold: int) -> bool:
        return self.bytes_sent >= threshold

    def is_expired(self, timeout_seconds: float) -> bool:
        return (time.time() - self.last_activity_time) > timeout_seconds

    def next_send_seq(self) -> int:
        self.send_seq += 1
        return self.send_seq

    def validate_incoming_seq(self, seq: int) -> bool:
        return self.replay_window.validate_and_update(seq)
