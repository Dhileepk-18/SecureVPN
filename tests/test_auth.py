import unittest
import time
from auth.passwords import hash_password, verify_password, RateLimiter

class TestAuthSecurity(unittest.TestCase):

    def test_password_hashing_and_verification(self):
        password = "mysecretpassword123"
        hashed = hash_password(password)

        self.assertNotEqual(password, hashed)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))

    def test_rate_limiter_lockout(self):
        limiter = RateLimiter(max_attempts=3, lockout_seconds=1.0)
        user = "testuser"

        self.assertFalse(limiter.is_locked(user))

        limiter.record_failure(user)
        limiter.record_failure(user)
        self.assertFalse(limiter.is_locked(user))

        limiter.record_failure(user)  # 3rd failure
        self.assertTrue(limiter.is_locked(user))

        time.sleep(1.1)  # Wait for lockout period to expire
        self.assertFalse(limiter.is_locked(user))

if __name__ == '__main__':
    unittest.main()
