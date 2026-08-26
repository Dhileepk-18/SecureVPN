import socket
import threading
import time
import sys
import config

from crypto.key_exchange import generate_x25519_keypair, perform_key_exchange
from crypto.key_derivation import derive_traffic_keys
from crypto.signatures import sign_data
from crypto.certificates import verify_certificate
from cryptography.hazmat.primitives import serialization
from protocol import (
    send_frame, recv_frame, send_secure_packet, recv_secure_packet,
    MSG_AUTH, MSG_DATA, MSG_PING, MSG_PONG, MSG_SPEED_TEST, MSG_CLOSE, MSG_HEARTBEAT, MSG_KEY_ROTATION
)
from session.manager import SessionManager
from auth.passwords import verify_password, RateLimiter
from monitoring.metrics import MetricsCollector
from monitoring.logging_config import setup_logger
from monitoring.dashboard import TelemetryDashboard

logger = setup_logger("Server")

with open("server_identity.pem", "rb") as f:
    SERVER_IDENTITY_KEY = serialization.load_pem_private_key(f.read(), password=None)

with open("certs/ca.crt", "rb") as f:
    CA_CERT_PEM = f.read()

with open("certs/server.crt", "rb") as f:
    SERVER_CERT_PEM = f.read()

session_manager = SessionManager()
metrics = MetricsCollector()
dashboard = TelemetryDashboard(metrics)
rate_limiter = RateLimiter(config.MAX_LOGIN_ATTEMPTS, config.LOCKOUT_TIME_SECONDS)

def handle_client(conn: socket.socket, addr):
    logger.info(f"New connection initiated from {addr}")
    metrics.record_connection_start()
    session = None
    try:
        conn.settimeout(config.HEARTBEAT_TIMEOUT)

        # STEP 1: HANDSHAKE
        send_frame(conn, SERVER_CERT_PEM)

        client_cert_pem = recv_frame(conn)
        if not client_cert_pem or not verify_certificate(client_cert_pem, CA_CERT_PEM):
            logger.security(f"Rejected connection from {addr}: Invalid/Untrusted Client X.509 Certificate")
            raise Exception("Client certificate verification failed")

        logger.info(f"Mutual mTLS Certificate verified successfully for {addr}")

        server_private_key, server_pub_pem = generate_x25519_keypair()
        signature = sign_data(SERVER_IDENTITY_KEY, server_pub_pem)
        send_frame(conn, server_pub_pem)
        send_frame(conn, signature)

        client_pub_pem = recv_frame(conn)
        if not client_pub_pem:
            raise Exception("Client disconnected during key exchange")

        shared_secret = perform_key_exchange(server_private_key, client_pub_pem)
        c2s_key, s2s_key = derive_traffic_keys(shared_secret)

        session = session_manager.create_session(addr, c2s_key, s2s_key)
        logger.info(f"Session ID {session.session_id[:8]} active for {addr}")

        # STEP 2: AUTHENTICATION
        msg_type, seq_num, auth_payload = recv_secure_packet(conn, session.current_c2s_key)
        if msg_type != MSG_AUTH or not session.validate_incoming_seq(seq_num):
            metrics.record_replay_drop()
            logger.security(f"Dropped invalid/replayed authentication packet from {addr}")
            raise Exception("Invalid authentication packet")

        metrics.record_bytes_received(len(auth_payload))
        session.touch_activity(len(auth_payload))
        auth_str = auth_payload.decode('utf-8')
        _, username, password = auth_str.split(":", 2)

        if rate_limiter.is_locked(username):
            metrics.record_login_failure()
            logger.security(f"Blocked locked login attempt for user '{username}' from {addr}")
            send_secure_packet(conn, MSG_AUTH, session.next_send_seq(), "AUTH_FAIL: Locked", session.current_s2s_key)
            raise Exception("Account locked")

        stored_hash = config.ALLOWED_USERS.get(username)
        if stored_hash and verify_password(password, stored_hash):
            session.username = username
            rate_limiter.record_success(username)
            metrics.record_login_success()
            logger.info(f"User '{username}' authenticated successfully from {addr}")
            send_secure_packet(conn, MSG_AUTH, session.next_send_seq(), "AUTH_OK", session.current_s2s_key)
            metrics.record_bytes_sent(7)
        else:
            rate_limiter.record_failure(username)
            metrics.record_login_failure()
            logger.warning(f"Failed authentication attempt for user '{username}' from {addr}")
            time.sleep(1.0)
            send_secure_packet(conn, MSG_AUTH, session.next_send_seq(), "AUTH_FAIL: Invalid credentials", session.current_s2s_key)
            raise Exception("Authentication failed")

        # STEP 3: SECURE SESSION LOOP
        while True:
            try:
                msg_type, seq_num, payload = recv_secure_packet(conn, session.current_c2s_key)
            except socket.timeout:
                logger.warning(f"Client {addr} silent for {config.HEARTBEAT_TIMEOUT}s. Session timed out.")
                break

            if msg_type is None:
                break

            if not session.validate_incoming_seq(seq_num):
                metrics.record_replay_drop()
                logger.security(f"Replayed/Invalid Packet dropped! Seq: {seq_num} from {addr}")
                continue

            metrics.record_bytes_received(len(payload))
            session.touch_activity(len(payload))

            if msg_type == MSG_KEY_ROTATION or session.should_rotate_keys(config.KEY_ROTATION_BYTE_THRESHOLD):
                session.rotate_session_keys()
                metrics.record_key_rotation()
                logger.info(f"Rotated traffic keys to Epoch {session.epoch} for user '{username}' ({addr})")
                send_secure_packet(conn, MSG_KEY_ROTATION, session.next_send_seq(), f"EPOCH:{session.epoch}", session.current_s2s_key)
                continue

            if msg_type == MSG_HEARTBEAT:
                send_secure_packet(conn, MSG_HEARTBEAT, session.next_send_seq(), b"HEARTBEAT_ACK", session.current_s2s_key)
                metrics.record_bytes_sent(13)

            elif msg_type == MSG_PING:
                send_secure_packet(conn, MSG_PONG, session.next_send_seq(), b"PONG", session.current_s2s_key)
                metrics.record_bytes_sent(4)

            elif msg_type == MSG_CLOSE:
                logger.info(f"Graceful disconnect request received from {addr}")
                break

            elif msg_type == MSG_SPEED_TEST:
                logger.info(f"Speed test initiated by user '{username}' ({addr})")
                total_bytes = 0
                start_time = time.time()

                while True:
                    m_type, s_num, chunk = recv_secure_packet(conn, session.current_c2s_key)
                    if m_type is None or not session.validate_incoming_seq(s_num):
                        break
                    metrics.record_bytes_received(len(chunk))
                    session.touch_activity(len(chunk))

                    if session.should_rotate_keys(config.KEY_ROTATION_BYTE_THRESHOLD):
                        session.rotate_session_keys()
                        metrics.record_key_rotation()
                        logger.info(f"Rotated keys during speed test to Epoch {session.epoch}")

                    if chunk == b"TEST_SPEED_END":
                        break
                    total_bytes += len(chunk)

                duration = max(time.time() - start_time, 0.000001)
                mbps = (total_bytes * 8) / duration / 1_000_000
                total_mb = total_bytes / (1024 * 1024)

                res = f"Speed test complete. Server recorded {mbps:.2f} Mbps ({total_mb:.2f} MB)."
                send_secure_packet(conn, MSG_DATA, session.next_send_seq(), res, session.current_s2s_key)
                metrics.record_bytes_sent(len(res))

            elif msg_type == MSG_DATA:
                msg_str = payload.decode('utf-8')
                logger.debug(f"Data frame from {username} ({addr}): Seq {seq_num}")
                echo_reply = f"Server echoes: {msg_str}"
                send_secure_packet(conn, MSG_DATA, session.next_send_seq(), echo_reply, session.current_s2s_key)
                metrics.record_bytes_sent(len(echo_reply))

    except Exception as e:
        logger.error(f"Error handling client {addr}: {e}")
    finally:
        metrics.record_connection_end()
        if session:
            session_manager.remove_session(session.session_id)
        logger.info(f"Client {addr} disconnected cleanly.")
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.HOST, config.PORT))
    server.listen(5)
    logger.info(f"SecureVPN Server active and listening on {config.HOST}:{config.PORT}")

    # Launch Dashboard UI if '--dashboard' flag is passed
    if "--dashboard" in sys.argv:
        threading.Thread(target=dashboard.start_cli_loop, daemon=True).start()

    while True:
        try:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
        except KeyboardInterrupt:
            logger.info("Server shutting down cleanly...")
            logger.info(f"Telemetry Summary: {metrics.get_summary()}")
            server.close()
            break

if __name__ == "__main__":
    start_server()
