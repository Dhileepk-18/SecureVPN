import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_ca():
    """Generates a self-signed Root Certificate Authority (CA) keypair and certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureVPN Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureVPN Security Inc"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(hours=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    return ca_key, ca_cert

def generate_signed_cert(common_name: str, ca_key, ca_cert):
    """Generates a client/server certificate signed by the Root CA."""
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        cert_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(hours=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    return cert_key, cert

def verify_certificate(cert_pem: bytes, ca_cert_pem: bytes) -> bool:
    """Validates X.509 certificate signature, validity date range, and CA trust."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False

        # RSA signature verification requires PKCS1v15 padding
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False
