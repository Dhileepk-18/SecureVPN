import unittest
import time
from session.session import Session

class TestSessionHeartbeat(unittest.TestCase):

    def test_session_activity_touch_and_expiration(self):
        c2s_key = b"1" * 32
        s2s_key = b"2" * 32
        session = Session("127.0.0.1", c2s_key, s2s_key)

        # Initially active
        self.assertFalse(session.is_expired(timeout_seconds=1.0))

        # Wait for timeout period
        time.sleep(1.1)
        self.assertTrue(session.is_expired(timeout_seconds=1.0))

        # Touch activity (e.g. heartbeat received)
        session.touch_activity()
        self.assertFalse(session.is_expired(timeout_seconds=1.0))

if __name__ == '__main__':
    unittest.main()
