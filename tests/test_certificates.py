import unittest
from crypto.certificates import generate_ca, generate_signed_cert, verify_certificate
from cryptography.hazmat.primitives import serialization

class TestCertificateSecurity(unittest.TestCase):

    def test_valid_certificate_chain(self):
        ca_key, ca_cert = generate_ca()
        client_key, client_cert = generate_signed_cert("client.test", ca_key, ca_cert)

        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        client_pem = client_cert.public_bytes(serialization.Encoding.PEM)

        self.assertTrue(verify_certificate(client_pem, ca_pem))

    def test_untrusted_certificate_rejection(self):
        ca_key1, ca_cert1 = generate_ca()
        ca_key2, ca_cert2 = generate_ca()

        client_key, client_cert = generate_signed_cert("untrusted.test", ca_key1, ca_cert1)

        ca2_pem = ca_cert2.public_bytes(serialization.Encoding.PEM)
        client_pem = client_cert.public_bytes(serialization.Encoding.PEM)

        self.assertFalse(verify_certificate(client_pem, ca2_pem))

if __name__ == '__main__':
    unittest.main()
