from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_identity_keypair():
    """Generates a long-term Ed25519 identity keypair for server authentication."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Signs bytes using the Ed25519 private key."""
    return private_key.sign(data)

def verify_signature(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Verifies an Ed25519 signature against data. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_bytes)
