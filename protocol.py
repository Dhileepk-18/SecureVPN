import socket
from crypto.aead import encrypt_gcm, decrypt_gcm
import config

HEADER_SIZE = 4

MSG_AUTH = 1
MSG_DATA = 2
MSG_PING = 3
MSG_PONG = 4
MSG_SPEED_TEST = 5
MSG_CLOSE = 6
MSG_HEARTBEAT = 7
MSG_KEY_ROTATION = 8  # Key rotation signal

def send_frame(sock: socket.socket, payload: bytes):
    if len(payload) > config.MAX_FRAME_SIZE:
        raise ValueError("Payload exceeds maximum allowable frame size")
    length_header = len(payload).to_bytes(HEADER_SIZE, 'big')
    sock.sendall(length_header + payload)

def recv_frame(sock: socket.socket) -> bytes:
    length_bytes = recv_all(sock, HEADER_SIZE)
    if not length_bytes:
        return None
    frame_length = int.from_bytes(length_bytes, 'big')
    if frame_length > config.MAX_FRAME_SIZE:
        raise ValueError("Incoming frame size exceeds safety limit")
    return recv_all(sock, frame_length)

def recv_all(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def pack_packet(msg_type: int, seq_num: int, payload: bytes) -> bytes:
    return msg_type.to_bytes(1, 'big') + seq_num.to_bytes(8, 'big') + payload

def unpack_packet(raw_bytes: bytes):
    if len(raw_bytes) < 9:
        raise ValueError("Packet payload too short")
    msg_type = raw_bytes[0]
    seq_num = int.from_bytes(raw_bytes[1:9], 'big')
    payload = raw_bytes[9:]
    return msg_type, seq_num, payload

def send_secure_packet(sock: socket.socket, msg_type: int, seq_num: int, message, send_key: bytes):
    if isinstance(message, str):
        message = message.encode('utf-8')
    packet_data = pack_packet(msg_type, seq_num, message)
    ciphertext = encrypt_gcm(packet_data, send_key)
    send_frame(sock, ciphertext)

def recv_secure_packet(sock: socket.socket, recv_key: bytes):
    ciphertext = recv_frame(sock)
    if ciphertext is None:
        return None, None, None
    decrypted_bytes = decrypt_gcm(ciphertext, recv_key)
    return unpack_packet(decrypted_bytes)
