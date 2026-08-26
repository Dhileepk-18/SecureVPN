import bcrypt
import time

class RateLimiter:
    """Tracks failed login attempts and enforces lockout delays."""
    def __init__(self, max_attempts: int = 3, lockout_seconds: float = 5.0):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.attempts = {}  # username -> (failed_count, last_attempt_time)

    def is_locked(self, username: str) -> bool:
        if username not in self.attempts:
            return False
        failed_count, last_time = self.attempts[username]
        if failed_count >= self.max_attempts:
            if time.time() - last_time < self.lockout_seconds:
                return True
            else:
                del self.attempts[username]
                return False
        return False

    def record_failure(self, username: str):
        now = time.time()
        if username in self.attempts:
            failed_count, _ = self.attempts[username]
            self.attempts[username] = (failed_count + 1, now)
        else:
            self.attempts[username] = (1, now)

    def record_success(self, username: str):
        if username in self.attempts:
            del self.attempts[username]

def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt with a salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False
