import unittest
from session.session import Session

class TestKeyRotation(unittest.TestCase):

    def test_key_rotation_progression(self):
        c2s_key = b"1" * 32
        s2s_key = b"2" * 32
        session = Session("127.0.0.1", c2s_key, s2s_key)

        initial_epoch = session.epoch
        initial_c2s = session.current_c2s_key

        # Rotate key
        session.rotate_session_keys()

        self.assertEqual(session.epoch, initial_epoch + 1)
        self.assertNotEqual(session.current_c2s_key, initial_c2s)
        self.assertEqual(len(session.current_c2s_key), 32)

    def test_byte_threshold_trigger(self):
        c2s_key = b"1" * 32
        s2s_key = b"2" * 32
        session = Session("127.0.0.1", c2s_key, s2s_key)

        self.assertFalse(session.should_rotate_keys(threshold=1000))
        session.touch_activity(bytes_count=1000)
        self.assertTrue(session.should_rotate_keys(threshold=1000))

if __name__ == '__main__':
    unittest.main()
