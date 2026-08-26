import unittest
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature
from crypto.key_exchange import generate_x25519_keypair

class TestHandshakeSecurity(unittest.TestCase):

    def test_signature_generation_and_verification(self):
        priv_key, pub_key = generate_identity_keypair()
        _, ephemeral_pub = generate_x25519_keypair()

        signature = sign_data(priv_key, ephemeral_pub)

        self.assertTrue(verify_signature(pub_key, signature, ephemeral_pub))

    def test_tampered_handshake_rejection(self):
        priv_key, pub_key = generate_identity_keypair()
        _, ephemeral_pub = generate_x25519_keypair()

        signature = sign_data(priv_key, ephemeral_pub)

        # Attacker tampers with the ephemeral public key
        tampered_pub = bytearray(ephemeral_pub)
        tampered_pub[10] ^= 0xFF

        self.assertFalse(verify_signature(pub_key, signature, bytes(tampered_pub)))

if __name__ == '__main__':
    unittest.main()
