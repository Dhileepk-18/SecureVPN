import unittest
from crypto.aead import encrypt_gcm, decrypt_gcm
from crypto.key_exchange import generate_x25519_keypair, perform_key_exchange
from crypto.key_derivation import derive_traffic_keys

class TestSecureVPNCrypto(unittest.TestCase):

    def test_x25519_key_exchange(self):
        client_priv, client_pub = generate_x25519_keypair()
        server_priv, server_pub = generate_x25519_keypair()

        client_shared = perform_key_exchange(client_priv, server_pub)
        server_shared = perform_key_exchange(server_priv, client_pub)

        self.assertEqual(client_shared, server_shared)

    def test_traffic_key_derivation(self):
        shared_secret = b"0" * 32
        c2s_key, s2s_key = derive_traffic_keys(shared_secret)

        self.assertEqual(len(c2s_key), 32)
        self.assertEqual(len(s2s_key), 32)
        self.assertNotEqual(c2s_key, s2s_key)

    def test_aead_encryption_decryption(self):
        key = b"1" * 32
        plaintext = b"Hello SecureVPN!"

        ciphertext = encrypt_gcm(plaintext, key)
        decrypted = decrypt_gcm(ciphertext, key)

        self.assertEqual(plaintext, decrypted)

    def test_tampered_ciphertext_rejection(self):
        key = b"1" * 32
        plaintext = b"Tamper test message"

        ciphertext = bytearray(encrypt_gcm(plaintext, key))
        ciphertext[-1] ^= 0xFF

        with self.assertRaises(ValueError):
            decrypt_gcm(bytes(ciphertext), key)

if __name__ == '__main__':
    unittest.main()
