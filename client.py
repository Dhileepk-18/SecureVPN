import socket
import threading
import time
from getpass import getpass
import config

from crypto.key_exchange import generate_x25519_keypair, perform_key_exchange
from crypto.key_derivation import derive_traffic_keys
from crypto.signatures import load_public_key_pem, verify_signature
from crypto.certificates import verify_certificate
from protocol import (
    send_frame, recv_frame, send_secure_packet, recv_secure_packet,
    MSG_AUTH, MSG_DATA, MSG_PING, MSG_PONG, MSG_SPEED_TEST, MSG_CLOSE, MSG_HEARTBEAT, MSG_KEY_ROTATION
)
from session.session import Session

with open("server_identity_pub.pem", "rb") as f:
    SERVER_IDENTITY_PUBKEY = load_public_key_pem(f.read())

with open("certs/ca.crt", "rb") as f:
    CA_CERT_PEM = f.read()

with open("certs/client.crt", "rb") as f:
    CLIENT_CERT_PEM = f.read()

ping_start_time = None
is_running = True

def heartbeat_sender(sock: socket.socket, session: Session):
    global is_running
    while is_running:
        try:
            time.sleep(config.HEARTBEAT_INTERVAL)
            if is_running:
                send_secure_packet(sock, MSG_HEARTBEAT, session.next_send_seq(), b"HEARTBEAT", session.current_c2s_key)
        except Exception:
            break

def listen_for_server(sock: socket.socket, session: Session):
    global ping_start_time, is_running
    while is_running:
        try:
            msg_type, seq_num, payload = recv_secure_packet(sock, session.current_s2s_key)
            if msg_type is None:
                is_running = False
                break

            if not session.validate_incoming_seq(seq_num):
                continue

            session.touch_activity(len(payload))

            if msg_type == MSG_KEY_ROTATION:
                session.rotate_session_keys()
                print(f"\r[KEY ROTATION] Session keys rotated to Epoch {session.epoch}.\n[CLIENT] > ", end="")

            elif msg_type == MSG_HEARTBEAT:
                pass

            elif msg_type == MSG_PONG and ping_start_time is not None:
                latency = (time.time() - ping_start_time) * 1000
                print(f"\r[REPLY] Latency: {latency:.2f} ms\n[CLIENT] > ", end="")
                ping_start_time = None

            elif msg_type == MSG_DATA:
                msg_str = payload.decode('utf-8')
                print(f"\r[SERVER] {msg_str}\n[CLIENT] > ", end="")
        except Exception:
            is_running = False
            break

def connect_and_authenticate():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((config.HOST, config.PORT))

    server_cert_pem = recv_frame(client_socket)
    if not verify_certificate(server_cert_pem, CA_CERT_PEM):
        raise Exception("Server Certificate Verification Failed!")

    send_frame(client_socket, CLIENT_CERT_PEM)

    server_pub_pem = recv_frame(client_socket)
    signature = recv_frame(client_socket)

    if not verify_signature(SERVER_IDENTITY_PUBKEY, signature, server_pub_pem):
        raise Exception("Ed25519 Signature Verification Failed!")

    client_private_key, client_pub_pem = generate_x25519_keypair()
    send_frame(client_socket, client_pub_pem)

    shared_secret = perform_key_exchange(client_private_key, server_pub_pem)
    c2s_key, s2s_key = derive_traffic_keys(shared_secret)

    session = Session((config.HOST, config.PORT), c2s_key, s2s_key)
    return client_socket, session

def start_client():
    global is_running, ping_start_time
    
    backoff = 1.0
    client_socket = None
    session = None
    
    for attempt in range(1, config.MAX_RECONNECT_ATTEMPTS + 1):
        try:
            print(f"[CONNECTION] Connecting to {config.HOST}:{config.PORT} (Attempt {attempt})...")
            client_socket, session = connect_and_authenticate()
            print("[CONNECTION] Connected & Authenticated successfully.")
            break
        except Exception as e:
            print(f"[RECONNECT] Connection failed: {e}. Retrying in {backoff:.1f}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 10.0)

    if not client_socket:
        print("[ERROR] Max reconnection attempts reached. Exiting.")
        return

    try:
        username = input("Enter username: ")
        password = getpass("Enter password: ")

        auth_str = f"AUTH:{username}:{password}"
        send_secure_packet(client_socket, MSG_AUTH, session.next_send_seq(), auth_str, session.current_c2s_key)

        m_type, s_num, auth_resp = recv_secure_packet(client_socket, session.current_s2s_key)
        if not auth_resp or auth_resp.decode('utf-8') != "AUTH_OK":
            print(f"[AUTH] Failed: {auth_resp.decode('utf-8') if auth_resp else 'No response'}")
            return

        print(f"[AUTH] Successfully authenticated as '{username}'.")
        print("Available commands: 'ping', 'test_speed', 'quit', or type any message.")

        is_running = True
        
        threading.Thread(target=listen_for_server, args=(client_socket, session), daemon=True).start()
        threading.Thread(target=heartbeat_sender, args=(client_socket, session), daemon=True).start()

        while is_running:
            msg = input("[CLIENT] > ")
            if not is_running:
                break

            cmd = msg.lower()
            if cmd == "quit":
                send_secure_packet(client_socket, MSG_CLOSE, session.next_send_seq(), b"CLOSE", session.current_c2s_key)
                is_running = False
                break

            elif cmd == "ping":
                ping_start_time = time.time()
                send_secure_packet(client_socket, MSG_PING, session.next_send_seq(), b"PING", session.current_c2s_key)

            elif cmd == "test_speed":
                print("[SPEED TEST] Sending 10 MB payload...")
                send_secure_packet(client_socket, MSG_SPEED_TEST, session.next_send_seq(), b"START", session.current_c2s_key)

                target_bytes = 10 * 1024 * 1024
                chunk = b'X' * 64512
                sent_bytes = 0

                while sent_bytes < target_bytes:
                    if session.should_rotate_keys(config.KEY_ROTATION_BYTE_THRESHOLD):
                        session.rotate_session_keys()
                        send_secure_packet(client_socket, MSG_KEY_ROTATION, session.next_send_seq(), b"ROTATE", session.current_c2s_key)

                    send_secure_packet(client_socket, MSG_SPEED_TEST, session.next_send_seq(), chunk, session.current_c2s_key)
                    sent_bytes += len(chunk)
                    session.touch_activity(len(chunk))

                send_secure_packet(client_socket, MSG_SPEED_TEST, session.next_send_seq(), b"TEST_SPEED_END", session.current_c2s_key)
                print("[SPEED TEST] Transfer complete. Awaiting server report...")

            else:
                send_secure_packet(client_socket, MSG_DATA, session.next_send_seq(), msg, session.current_c2s_key)

    except Exception as e:
        print(f"[ERROR] Session terminated: {e}")
    finally:
        is_running = False
        if client_socket:
            client_socket.close()

if __name__ == "__main__":
    start_client()
