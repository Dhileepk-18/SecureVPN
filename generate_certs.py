import os
from crypto.certificates import generate_ca, generate_signed_cert
from cryptography.hazmat.primitives import serialization

os.makedirs('certs', exist_ok=True)

# 1. Generate Root CA
ca_key, ca_cert = generate_ca()
open('certs/ca.crt', 'wb').write(ca_cert.public_bytes(serialization.Encoding.PEM))

# 2. Generate Server Certificate
s_key, s_cert = generate_signed_cert('vpn-server.local', ca_key, ca_cert)
open('certs/server.crt', 'wb').write(s_cert.public_bytes(serialization.Encoding.PEM))
open('certs/server.key', 'wb').write(s_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

# 3. Generate Client Certificate
c_key, c_cert = generate_signed_cert('vpn-client.local', ca_key, ca_cert)
open('certs/client.crt', 'wb').write(c_cert.public_bytes(serialization.Encoding.PEM))
open('certs/client.key', 'wb').write(c_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

print("X.509 Certificates (Root CA, Server, Client) generated successfully in certs/")
