from session.session import Session

class SessionManager:
    """Tracks active sessions on the server."""
    def __init__(self):
        self.active_sessions = {}  # session_id -> Session

    def create_session(self, peer_addr, c2s_key: bytes, s2s_key: bytes) -> Session:
        sess = Session(peer_addr, c2s_key, s2s_key)
        self.active_sessions[sess.session_id] = sess
        return sess

    def get_session(self, session_id: str) -> Session:
        return self.active_sessions.get(session_id)

    def remove_session(self, session_id: str):
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]

    def count(self) -> int:
        return len(self.active_sessions)
