import os
from Crypto.Cipher import AES

NONCE_SIZE = 12
TAG_SIZE = 16

def encrypt_gcm(message: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce + tag + ciphertext

def decrypt_gcm(encrypted_payload: bytes, key: bytes) -> bytes:
    if len(encrypted_payload) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Payload too short for AES-GCM decryption")
    
    nonce = encrypted_payload[:NONCE_SIZE]
    tag = encrypted_payload[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_payload[NONCE_SIZE + TAG_SIZE:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
