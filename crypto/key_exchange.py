from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem

def perform_key_exchange(private_key, peer_public_pem: bytes) -> bytes:
    peer_public_key = load_pem_public_key(peer_public_pem)
    return private_key.exchange(peer_public_key)
