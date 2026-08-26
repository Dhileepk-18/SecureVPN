# SecureVPN — Production-Grade Ephemeral Encrypted Tunnel
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security Suite](https://img.shields.io/badge/tests-24%20passed-success.svg)](./tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
**SecureVPN** is a high-performance, multi-threaded, authenticated, encrypted TCP tunneling application implemented in Python. Designed according to modern security principles (**TLS 1.3, WireGuard, and IPsec RFC 4303**), it delivers end-to-end confidentiality, authenticity, perfect forward secrecy, and real-time telemetry.
---
## Key Features
- 🔐 **AEAD Authenticated Encryption**: AES-256-GCM with fresh 12-byte random nonces and 16-byte authentication tags.
- ⚡ **Ephemeral Key Exchange**: Curve25519 (`X25519`) Diffie-Hellman key agreement for sub-millisecond session key setup.
- 🔏 **Digital Signatures & MitM Prevention**: `Ed25519` server identity signing keys protect key exchanges against active tampering.
- 📜 **Mutual Certificate Authentication (mTLS)**: Local Public Key Infrastructure (PKI) validating X.509 v3 certificate chains signed by a Root Certificate Authority (CA).
- 🛡️ **Anti-Replay Sliding Window**: 64-bit sliding bitmask window (RFC 4303 style) rejecting replayed and out-of-order injected packets.
- 🔄 **Automatic Key Rotation (Epochs)**: Automatic HKDF-SHA256 re-keying triggered after transferring 2 MB of data.
- 🔑 **Salted Password Hashing**: `Bcrypt` password verification (cost factor = 12) with account lockout rate-limiting against brute-force guessing.
- 💓 **Session Management & Heartbeats**: Periodic keep-alive heartbeats with automatic 15-second dead-client detection and exponential backoff reconnection.
- 📊 **Real-Time Telemetry Dashboard**: Live interactive CLI terminal dashboard monitoring network throughput (MB sent/recvd), active connections, key rotations, and security drops.
---
## Architecture & Threat Model
```text
[Client]                                                            [Server]
   |                                                                   |
   |--- 1. Mutual X.509 Certificate Authentication (mTLS) ------------>|
   |--- 2. Ed25519 Signed X25519 Ephemeral Exchange (PFS) ------------>|
   |--- 3. Salted Bcrypt Authentication + Rate Limiter ------------->|
   |<== 4. AES-256-GCM Encrypted Tunnel Established (Directional Keys)=|
   |                                                                   |
   |--- 5. 64-bit Anti-Replay Sliding Window Protection -------------->|
   |--- 6. Heartbeat Keep-Alive & Dead-Client Timeout (15s) ---------->|
   |--- 7. Automatic Key Rotation (Epochs after 2MB Data) ------------>|
   |--- 8. Real-time Network Telemetry & Metrics Engine -------------->|
Mitigated Threat Matrix
Threat Vector	Mitigation Strategy	Cryptographic Primitive
Eavesdropping / Packet Sniffing	AEAD Authenticated Encryption	AES-256-GCM
Active Man-in-the-Middle (MitM)	Signed Ephemeral Exchange	Ed25519 Signatures + X25519
Impersonation / Spoofing	Mutual Certificate Authentication	X.509 Root CA (mTLS)
Future Key Leakage	Perfect Forward Secrecy	Ephemeral X25519 + HKDF-SHA256
Replay Attacks	Sliding Bitmask Window	64-bit Replay Window (RFC 4303)
Password Database Leak	Salted Password Hashing	Bcrypt (Rounds=12)
Brute-force Login Attacks	Rate Limiter + Lockout	Exponential Delay + 5s Lockout
Long-lived Session Exposure	Key Rotation Epochs	HKDF Re-keying (Every 2 MB)
Silent Disconnects	Heartbeat Keep-Alive	15s Inactivity Dead-Client Drop
Repository Structure
text


securevpn/
├── config.py                   # Master configuration & .env loader
├── protocol.py                 # Length-prefixed framing & packet type definitions
├── server.py                   # Multi-threaded VPN server with telemetry & key rotation
├── client.py                   # Interactive CLI client with auto-reconnect & heartbeats
├── generate_certs.py           # PKI Certificate Authority generator
├── requirements.txt            # Python dependencies
├── .env / .env.example         # Environment variables
├── server_identity.pem         # Server Ed25519 private identity key
├── server_identity_pub.pem     # Server Ed25519 public identity key
├── certs/                      # X.509 PKI certificates directory
├── crypto/                     # Cryptographic subsystem (AES-GCM, X25519, HKDF, Ed25519, X.509)
├── auth/                       # Authentication subsystem (Bcrypt & Rate Limiter)
├── session/                    # Session subsystem (Session Objects & 64-bit Anti-Replay)
├── monitoring/                 # Telemetry & Logging subsystem (Metrics, Logger, CLI Dashboard)
└── tests/                      # Automated test suite (24 Unit & Fuzzing tests)
Installation & Setup (Ubuntu / Linux)
1. Clone & Install Dependencies
bash


git clone https://github.com/Dhileepk-18/SecureVPN.git
cd SecureVPN
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
2. Generate Identity Keys & X.509 Certificates
bash


# Generate server identity keypair
python3 -c "from crypto.signatures import generate_identity_keypair, export_public_key_pem; from cryptography.hazmat.primitives import serialization; priv, pub = generate_identity_keypair(); open('server_identity.pem', 'wb').write(priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())); open('server_identity_pub.pem', 'wb').write(export_public_key_pem(pub))"
# Generate Root CA, Server & Client X.509 Certificates
python3 generate_certs.py
Usage Guide
1. Run Automated Test Suite (24 Tests)
bash


python3 -m unittest discover -s tests -t .
2. Start the Server with Live Telemetry Dashboard
In Terminal 1:

bash


python3 server.py --dashboard
3. Start the Client CLI
In Terminal 2:

bash


python3 client.py
Username: dhileep
Password: pass1389
Interactive Commands:

ping: Measures end-to-end latency in milliseconds.
test_speed: Uploads 10 MB payload over AES-GCM to measure throughput (Mbps).
quit: Performs graceful disconnect request.
Portfolio & Resume Highlights
Custom Encrypted Tunnel: Built a high-performance Python encrypted socket tunnel leveraging X25519, Ed25519, and AES-256-GCM.
Mutual Certificate Authentication (mTLS): Implemented a local PKI infrastructure validating X.509 certificate chains and signatures.
Anti-Replay & Session Management: Engineered a 64-bit sliding window bitmask (RFC 4303) and automatic HKDF key rotation every 2 MB.
Telemetry & Monitoring: Built a real-time thread-safe metrics collector and live CLI terminal dashboard reporting network throughput and security events.
Full Test Coverage: Developed 24 automated unit and fuzzing security tests covering ciphertext bit-flipping, forged signatures, and sequence replay attacks.
License
Distributed under the MIT License. See LICENSE for more information.



---
### Commands to Save & Push to GitHub:
```bash
cd ~/securevpn
nano README.md
# Paste the content above, then press Ctrl+O -> Enter -> Ctrl+X
git add README.md
git commit -m "Add complete production-grade README documentation"
git push -u origin main --force
