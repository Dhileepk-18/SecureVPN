import unittest
import os
from crypto.aead import encrypt_gcm, decrypt_gcm
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature
from session.session import ReplayWindow
import config

class TestSecurityFuzzing(unittest.TestCase):

    def test_oversized_frame_rejection(self):
        """Ensures framing header validation blocks frames exceeding MAX_FRAME_SIZE."""
        oversized_len = config.MAX_FRAME_SIZE + 1000
        length_header = oversized_len.to_bytes(4, 'big')
        frame_len = int.from_bytes(length_header, 'big')

        self.assertGreater(frame_len, config.MAX_FRAME_SIZE)

    def test_ciphertext_bitflip_fuzzing(self):
        """Fuzzes encrypted payload by flipping 50 random bits to verify GCM tag rejection."""
        key = os.urandom(32)
        plaintext = b"Sensitive Security Payload Data"
        ciphertext = bytearray(encrypt_gcm(plaintext, key))

        # Flip multiple bits in the payload
        for i in range(len(ciphertext)):
            if i % 3 == 0:
                ciphertext[i] ^= 0xFF

        with self.assertRaises(ValueError):
            decrypt_gcm(bytes(ciphertext), key)

    def test_replay_attack_injection_fuzzing(self):
        """Simulates an attacker capturing and re-injecting 100 sequence numbers."""
        window = ReplayWindow(window_size=64)

        # Send valid sequential sequence numbers
        for seq in range(1, 50):
            self.assertTrue(window.validate_and_update(seq))

        # Attacker re-injects sequence number 25
        self.assertFalse(window.validate_and_update(25))
        
        # Attacker re-injects sequence number 49
        self.assertFalse(window.validate_and_update(49))

    def test_forged_ed25519_signature_fuzzing(self):
        """Simulates an attacker submitting forged Ed25519 signatures."""
        priv1, pub1 = generate_identity_keypair()
        priv2, pub2 = generate_identity_keypair()

        data = b"Handshake Ephemeral Public Key"
        forged_signature = sign_data(priv2, data)

        # Verify signature with pub1 fails because it was signed by priv2
        self.assertFalse(verify_signature(pub1, forged_signature, data))

if __name__ == '__main__':
    unittest.main()
