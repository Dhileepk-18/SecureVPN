import os
from dotenv import load_dotenv
from auth.passwords import hash_password

load_dotenv()

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))
LOCKOUT_TIME_SECONDS = float(os.getenv("LOCKOUT_TIME_SECONDS", "5.0"))

HEARTBEAT_INTERVAL = float(os.getenv("HEARTBEAT_INTERVAL", "5.0"))
HEARTBEAT_TIMEOUT = float(os.getenv("HEARTBEAT_TIMEOUT", "15.0"))
MAX_RECONNECT_ATTEMPTS = 5

# Key Rotation Threshold (Rotate session keys after transferring 2 MB)
KEY_ROTATION_BYTE_THRESHOLD = 2 * 1024 * 1024

ALLOWED_USERS = {
    "dhileep": hash_password("pass1389"),
    "satya": hash_password("pass1023"),
    "admin": hash_password("admin")
}

MAGIC_BYTES = b"VPN1"
MAX_FRAME_SIZE = 16 * 1024 * 1024
