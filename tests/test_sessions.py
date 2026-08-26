import unittest
from session.session import ReplayWindow, Session

class TestSessionSecurity(unittest.TestCase):

    def test_sequence_number_validation(self):
        window = ReplayWindow(window_size=64)

        self.assertTrue(window.validate_and_update(1))
        self.assertTrue(window.validate_and_update(2))
        self.assertTrue(window.validate_and_update(3))

        # Replayed packets must be rejected
        self.assertFalse(window.validate_and_update(2))
        self.assertFalse(window.validate_and_update(1))

    def test_out_of_order_packets(self):
        window = ReplayWindow(window_size=64)

        self.assertTrue(window.validate_and_update(10))
        self.assertTrue(window.validate_and_update(8))   # Out-of-order within window
        self.assertTrue(window.validate_and_update(9))   # Out-of-order within window

        self.assertFalse(window.validate_and_update(8))  # Duplicate rejected

    def test_outside_window_rejection(self):
        window = ReplayWindow(window_size=64)

        self.assertTrue(window.validate_and_update(100))
        self.assertFalse(window.validate_and_update(30))  # Older than last_seq - 64

if __name__ == '__main__':
    unittest.main()
