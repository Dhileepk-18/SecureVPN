# SecureVPN

### Production-Oriented Ephemeral Encrypted TCP Tunnel in Python

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%20X25519%20%7C%20Ed25519-0A0A0A)](https://github.com/Dhileepk-18/SecureVPN/tree/main/crypto)
[![Tests](https://img.shields.io/badge/Tests-24-success)](https://github.com/Dhileepk-18/SecureVPN/tree/main/tests)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SecureVPN** is a Python-based, multi-threaded encrypted TCP tunneling project focused on practical secure-session design, ephemeral key exchange, mutual certificate authentication, replay protection, automatic re-keying, authentication controls, and real-time telemetry.

> **Project status:** Portfolio / security-engineering project. The implementation demonstrates modern cryptographic building blocks and secure protocol concepts; it is **not intended to replace audited production VPN software such as WireGuard or IPsec**.

---

## Why SecureVPN?

SecureVPN was designed as a hands-on implementation of a secure tunnel rather than a simple encrypted socket. A session combines:

- **X25519** ephemeral Diffie–Hellman for forward-secret session material
- **Ed25519** signatures for server identity verification during the custom handshake
- **AES-256-GCM** for authenticated encryption of tunnel traffic
- **X.509 / mTLS** for certificate-based client/server authentication
- **HKDF-SHA256** for session-key derivation and periodic re-keying
- **Replay-window protection** to reject duplicate and stale packets
- **Bcrypt** password verification with login throttling / lockout controls
- **Heartbeats** and dead-peer detection for session lifecycle management
- **Thread-safe telemetry** for throughput and security-event visibility

The project is deliberately modular so that the cryptographic, authentication, session, protocol, and monitoring layers can be studied and tested independently.

---

## Security Architecture

```text
                           SECUREVPN SESSION

 ┌───────────────┐                                      ┌───────────────┐
 │    CLIENT     │                                      │     SERVER    │
 └───────┬───────┘                                      └───────┬───────┘
         │                                                      │
         │  1. X.509 mutual certificate authentication         │
         │─────────────────────────────────────────────────────>│
         │                                                      │
         │  2. Ephemeral X25519 exchange + Ed25519 signature   │
         │<────────────────────────────────────────────────────>│
         │                                                      │
         │  3. Password authentication + rate limiting          │
         │─────────────────────────────────────────────────────>│
         │                                                      │
         │  4. AES-256-GCM encrypted directional tunnel         │
         │<════════════════════════════════════════════════════>│
         │                                                      │
         │  5. Sequence numbers + replay-window validation       │
         │<════════════════════════════════════════════════════>│
         │                                                      │
         │  6. Heartbeats / dead-peer detection                  │
         │<────────────────────────────────────────────────────>│
         │                                                      │
         │  7. HKDF session re-keying after data threshold      │
         │<────────────────────────────────────────────────────>│
         │                                                      │
         │  8. Telemetry and security-event metrics              │
         │─────────────────────────────────────────────────────>│
```

### Threat model

| Threat | Mitigation | Primary mechanism |
|---|---|---|
| Passive packet capture | Authenticated encryption | AES-256-GCM |
| Active MITM during key exchange | Signed ephemeral exchange | Ed25519 + X25519 |
| Certificate impersonation | Mutual certificate validation | X.509 / mTLS |
| Session-key compromise risk | Ephemeral session keys | X25519 + HKDF-SHA256 |
| Replay / stale packets | Sliding replay window | Sequence numbers + bitmask |
| Password database exposure | Slow salted password hashing | Bcrypt |
| Online password guessing | Login throttling / lockout | Rate limiter |
| Long-lived key exposure | Periodic re-keying | HKDF-SHA256 epochs |
| Silent peer failure | Keep-alive and timeout | Heartbeats |

---

## Core Features

### Cryptography

- **AES-256-GCM** authenticated encryption
- Fresh **12-byte nonces** for encrypted records
- **16-byte GCM authentication tags**
- **X25519** ephemeral key agreement
- **Ed25519** identity signatures
- **HKDF-SHA256** key derivation and epoch-based re-keying
- **X.509 v3** certificate handling and local CA validation

### Session Security

- 64-bit replay-window / sliding-bitmask protection
- Sequence-number validation
- Directional session keys
- Automatic key rotation after the configured data threshold
- Heartbeat-based liveness detection
- Automatic reconnect behavior on the client

### Authentication

- Bcrypt password verification
- Configurable account protection / rate limiting
- Mutual certificate authentication
- Server identity verification

### Monitoring

- Live CLI telemetry dashboard
- Bytes sent / received
- Active connection tracking
- Key-rotation counters
- Security-drop counters
- Structured logging support

---

## Repository Structure

```text
SecureVPN/
├── auth/
│   └── passwords.py             # Bcrypt password handling / authentication controls
├── certs/
│   ├── ca.crt                   # Local CA certificate
│   ├── client.crt               # Client certificate
│   └── server.crt               # Server certificate
├── crypto/
│   ├── aead.py                  # AES-GCM encryption/decryption
│   ├── certificates.py          # X.509 certificate utilities
│   ├── key_derivation.py        # HKDF-SHA256 derivation
│   ├── key_exchange.py          # X25519 key exchange
│   └── signatures.py             # Ed25519 signing / verification
├── monitoring/
│   ├── dashboard.py             # Live terminal dashboard
│   ├── logging_config.py        # Logging configuration
│   └── metrics.py               # Thread-safe telemetry metrics
├── session/
│   ├── manager.py               # Session lifecycle management
│   └── session.py               # Session state / replay protection
├── tests/
│   ├── test_auth.py
│   ├── test_certificates.py
│   ├── test_crypto.py
│   ├── test_dashboard.py
│   ├── test_fuzzing.py
│   ├── test_handshake.py
│   ├── test_heartbeat.py
│   ├── test_key_rotation.py
│   └── ...
├── client.py                    # Interactive SecureVPN client
├── config.py                    # Environment-backed configuration
├── generate_certs.py            # Local PKI / certificate generator
├── protocol.py                  # Framing and packet definitions
├── server.py                    # Multi-threaded SecureVPN server
├── requirements.txt             # Python dependencies
├── .env.example                 # Example environment configuration
├── .gitignore
└── README.md
```

---

## Requirements

- Python **3.8+**
- Linux recommended for the current setup instructions
- A virtual environment is strongly recommended

Main dependencies currently include:

- `cryptography`
- `pycryptodome`
- `bcrypt`
- `python-dotenv`

See [`requirements.txt`](requirements.txt) for the project dependency specification.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Dhileepk-18/SecureVPN.git
cd SecureVPN
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the environment

Create your local `.env` from the example file:

```bash
cp .env.example .env
```

Then review the values before starting the server.

> **Never commit passwords, private keys, production certificates, or real secrets to Git.**

---

## Generate the Local PKI

SecureVPN uses a local certificate authority for the development/test environment.

### Generate the server identity keypair

```bash
python3 -c "from crypto.signatures import generate_identity_keypair, export_public_key_pem; from cryptography.hazmat.primitives import serialization; priv, pub = generate_identity_keypair(); open('server_identity.pem', 'wb').write(priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())); open('server_identity_pub.pem', 'wb').write(export_public_key_pem(pub))"
```

### Generate CA, server, and client certificates

```bash
python3 generate_certs.py
```

For anything beyond local development, use a properly managed PKI and protect private keys with appropriate filesystem and operational controls.

---

## Run the Test Suite

Run the automated test suite from the repository root:

```bash
python3 -m unittest discover -s tests -t .
```

The repository includes tests covering authentication, certificates, cryptographic operations, handshake behavior, heartbeat behavior, key rotation, dashboard/metrics behavior, and fuzz-style protocol/security cases.

---

## Start SecureVPN

### Terminal 1 — Server

```bash
python3 server.py --dashboard
```

### Terminal 2 — Client

```bash
python3 client.py
```

The client prompts for credentials and then exposes interactive commands such as:

```text
ping
```

Measures end-to-end latency.

```text
test_speed
```

Transfers a test payload through the encrypted tunnel to measure throughput.

```text
quit
```

Performs a graceful disconnect.

---

## Configuration

Configuration is centralized in `config.py` and can be populated through environment variables / `.env`.

Before deployment, review:

- Bind address and listening port
- Certificate and key paths
- Authentication settings
- Session timeout values
- Heartbeat interval
- Key-rotation threshold
- Logging / telemetry configuration

For security-sensitive deployments, prefer environment-managed secrets or a dedicated secret-management system over plaintext `.env` files.

---

## Security Design Notes

### Forward secrecy

Each session uses ephemeral X25519 key material. The resulting shared secret is passed through HKDF-SHA256 to derive session keys rather than using the raw Diffie–Hellman output directly.

### Authenticated encryption

Tunnel payloads are protected with AES-256-GCM. Confidentiality and integrity are therefore provided together, and modified ciphertext should fail authentication instead of being accepted as valid plaintext.

### Replay protection

Packets carry sequencing information that is evaluated against a sliding replay window. Previously accepted or sufficiently old sequence numbers are rejected.

### Key rotation

Session material is periodically refreshed using HKDF-based derivation after the configured data threshold. This limits the amount of traffic protected by a single session-key epoch.

### Identity and certificates

The project separates cryptographic identity signing from certificate-based authentication. Ed25519 is used for identity signatures while X.509 certificates provide the mTLS trust structure.

---

## Important Security Disclaimer

SecureVPN is an educational and portfolio-oriented implementation of a custom encrypted tunneling protocol.

It has **not** been independently audited and should not be considered equivalent to mature, widely deployed VPN implementations. Custom cryptographic protocols can contain subtle flaws even when they use strong primitives.

For real-world production VPN deployments, use established, audited protocols and implementations such as WireGuard or IPsec rather than deploying this project as an Internet-facing security boundary.

---

## What This Project Demonstrates

This repository is especially useful as a demonstration of:

- Secure protocol design
- Applied cryptography in Python
- Client/server networking
- Ephemeral key exchange
- Certificate-based authentication
- Replay protection
- Session lifecycle management
- Key derivation and re-keying
- Authentication hardening
- Multi-threaded server architecture
- Security-focused testing
- Real-time observability / telemetry

### Resume-ready summary

> **SecureVPN — Encrypted TCP Tunnel:** Designed and implemented a Python multi-threaded encrypted tunneling system using AES-256-GCM, X25519 ephemeral key exchange, Ed25519 identity signatures, X.509/mTLS authentication, HKDF-based key rotation, replay-window protection, Bcrypt authentication controls, heartbeat-based session management, and real-time telemetry. Built automated security-focused tests for cryptographic integrity, handshake behavior, replay handling, and protocol robustness.

---

## Development Roadmap

Potential next steps for the project:

- [ ] Add a formal protocol specification and versioning scheme
- [ ] Add explicit packet-size / resource-exhaustion limits
- [ ] Add CI with automated tests on supported Python versions
- [ ] Add static analysis and dependency vulnerability scanning
- [ ] Add integration tests for client/server sessions
- [ ] Improve certificate lifecycle and key storage handling
- [ ] Add configurable cipher-suite / protocol negotiation where appropriate
- [ ] Add structured JSON telemetry for external monitoring
- [ ] Add Linux service files for controlled local deployment
- [ ] Perform an independent security review before any production use

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Make your changes and add tests.
4. Run the complete test suite.
5. Open a pull request describing the security or engineering impact of the change.

Security-sensitive changes should include tests demonstrating both the intended behavior and relevant failure cases.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## Author

**Dhileepk-18**

GitHub: [@Dhileepk-18](https://github.com/Dhileepk-18)

Repository: [Dhileepk-18/SecureVPN](https://github.com/Dhileepk-18/SecureVPN)
