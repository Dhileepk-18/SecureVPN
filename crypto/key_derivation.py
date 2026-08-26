from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_traffic_keys(shared_secret: bytes):
    """Derives initial traffic keys for Epoch 0."""
    hkdf_c2s = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'securevpn-client-to-server'
    )
    c2s_key = hkdf_c2s.derive(shared_secret)

    hkdf_s2s = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'securevpn-server-to-client'
    )
    s2s_key = hkdf_s2s.derive(shared_secret)

    return c2s_key, s2s_key

def rotate_traffic_key(current_key: bytes, epoch: int, label: bytes) -> bytes:
    """Derives a new 32-byte key for the next Epoch using HKDF-SHA256."""
    info = label + b"-epoch-" + str(epoch).encode()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(current_key)
