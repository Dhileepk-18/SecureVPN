# SecureVPN

### Ephemeral Encrypted TCP Tunnel in Python

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%20X25519%20%7C%20Ed25519-0A0A0A)](crypto/)
[![Tests](https://img.shields.io/badge/Tests-24-success)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SecureVPN** is a Python-based, multi-threaded encrypted TCP tunneling application focused on secure session establishment, ephemeral key exchange, mutual certificate authentication, authenticated encryption, replay protection, automatic key rotation, authentication controls, session management, and real-time telemetry.

> **Security status:** This is a custom protocol implementation for development, testing, and security research. It has not been independently audited and should not be used as a replacement for established, audited VPN protocols in production environments.

---

## Features

### Cryptography

- **AES-256-GCM** authenticated encryption
- Fresh **12-byte nonces** for encrypted records
- **16-byte GCM authentication tags**
- **X25519** ephemeral Diffie–Hellman key exchange
- **Ed25519** identity signatures
- **HKDF-SHA256** key derivation and epoch-based re-keying
- **X.509 v3** certificate handling
- Local **Root CA** and mutual TLS authentication

### Session Security

- 64-bit sliding replay window
- Sequence-number validation
- Directional session keys
- Automatic key rotation after the configured data threshold
- Heartbeat-based liveness detection
- Dead-client detection
- Client reconnect handling

### Authentication

- Bcrypt password hashing and verification
- Login rate limiting / lockout controls
- Mutual certificate authentication
- Server identity verification

### Monitoring

- Live CLI telemetry dashboard
- Bytes sent / received
- Active connection tracking
- Key-rotation counters
- Security-drop counters
- Logging and metrics collection

---

## Architecture

```text
                           SECUREVPN SESSION

 ┌───────────────┐                                      ┌───────────────┐
 │    CLIENT     │                                      │     SERVER    │
 └───────┬───────┘                                      └───────┬───────┘
         │                                                      │
         │  1. Mutual X.509 certificate authentication          │
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

---

## Threat Model

| Threat | Mitigation | Mechanism |
|---|---|---|
| Passive packet capture | Authenticated encryption | AES-256-GCM |
| Active MITM during key exchange | Signed ephemeral exchange | Ed25519 + X25519 |
| Certificate impersonation | Mutual certificate validation | X.509 / mTLS |
| Session-key compromise risk | Ephemeral session keys | X25519 + HKDF-SHA256 |
| Replay / stale packets | Sliding replay window | Sequence numbers + bitmask |
| Password database exposure | Salted password hashing | Bcrypt |
| Online password guessing | Login throttling / lockout | Rate limiter |
| Long-lived key exposure | Periodic re-keying | HKDF-SHA256 epochs |
| Silent peer failure | Keep-alive and timeout | Heartbeats |

---

## Security Design

### Forward Secrecy

Each session uses ephemeral X25519 key material. The resulting shared secret is passed through HKDF-SHA256 to derive session keys rather than using the raw Diffie–Hellman output directly.

### Authenticated Encryption

Tunnel payloads are protected with AES-256-GCM, providing confidentiality and integrity for encrypted records. Modified ciphertext should fail authentication instead of being accepted as valid plaintext.

### Replay Protection

Packets carry sequencing information that is evaluated against a sliding replay window. Previously accepted or sufficiently old sequence numbers are rejected.

### Key Rotation

Session material is periodically refreshed using HKDF-based derivation after the configured data threshold, limiting the amount of traffic protected by a single session-key epoch.

### Identity and Certificates

Ed25519 signatures provide cryptographic identity verification during the custom handshake, while X.509 certificates provide the certificate-based trust structure used for mutual authentication.

### Authentication Protection

Passwords are verified using Bcrypt. Login attempts are subject to rate limiting and lockout controls to reduce online brute-force attempts.

### Session Liveness

Heartbeat messages provide connection liveness information. Clients that remain inactive beyond the configured timeout can be detected and removed by the server.

---

## Repository Structure

```text
SecureVPN/
├── auth/
│   └── passwords.py             # Bcrypt authentication and rate limiting
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
│   └── session.py               # Session state and replay protection
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
- A virtual environment is recommended

Current dependencies include:

- `cryptography`
- `pycryptodome`
- `bcrypt`
- `python-dotenv`

See [`requirements.txt`](requirements.txt) for the dependency specification.

---

## Installation

### Linux / Ubuntu

#### 1. Clone the repository

```bash
git clone https://github.com/Dhileepk-18/SecureVPN.git
cd SecureVPN
```

#### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install dependencies

```bash
pip install -r requirements.txt
```

#### 4. Configure the environment

Create a local `.env` file from the example configuration:

```bash
cp .env.example .env
```

Review the configuration before starting the server.

### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Do not commit passwords, private keys, production certificates, or other secrets to the repository.

---

## Certificate and Identity Setup

SecureVPN includes a local PKI generator for development and testing.

### Generate the server identity keypair

```bash
python3 -c "from crypto.signatures import generate_identity_keypair, export_public_key_pem; from cryptography.hazmat.primitives import serialization; priv, pub = generate_identity_keypair(); open('server_identity.pem', 'wb').write(priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())); open('server_identity_pub.pem', 'wb').write(export_public_key_pem(pub))"
```

### Generate the local CA and certificates

```bash
python3 generate_certs.py
```

This generates the certificate material used by the local development/test environment.

For deployment outside a controlled development environment, private keys and certificate lifecycle management should use appropriate security controls.

---

## Running the Test Suite

Run the automated tests from the repository root:

```bash
python3 -m unittest discover -s tests -t .
```

The test suite covers areas including:

- Authentication
- Certificate validation
- Cryptographic operations
- Handshake behavior
- Heartbeats
- Key rotation
- Session behavior
- Telemetry/dashboard behavior
- Protocol robustness and fuzz-style cases

---

## Running SecureVPN

### Start the server

In Terminal 1:

```bash
python3 server.py --dashboard
```

### Start the client

In Terminal 2:

```bash
python3 client.py
```

The client requests the configured credentials and establishes a secure session with the server.

### Interactive commands

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

Configuration is centralized in `config.py` and can be populated through environment variables and `.env`.

Review the following before running the application:

- Server bind address
- Server listening port
- Certificate paths
- Identity key paths
- Authentication settings
- Session timeout values
- Heartbeat settings
- Key-rotation threshold
- Logging configuration
- Telemetry settings

For security-sensitive environments, use an appropriate secret-management mechanism instead of storing sensitive values in plaintext `.env` files.

---

## Protocol Components

### Framing

`protocol.py` defines the length-prefixed transport framing and packet types used by the client and server.

### Cryptographic Layer

The `crypto/` package contains the cryptographic primitives and certificate utilities:

- `aead.py` — AES-GCM encryption and decryption
- `key_exchange.py` — X25519 key exchange
- `key_derivation.py` — HKDF-SHA256 derivation
- `signatures.py` — Ed25519 signatures
- `certificates.py` — X.509 certificate handling

### Authentication Layer

The `auth/` package provides Bcrypt password verification and authentication rate limiting.

### Session Layer

The `session/` package manages session state, lifecycle behavior, sequence numbers, and replay protection.

### Monitoring Layer

The `monitoring/` package provides metrics collection, logging, and the CLI telemetry dashboard.

---

## Development Roadmap

- [ ] Add a formal protocol specification and protocol versioning
- [ ] Add explicit packet-size and resource-exhaustion limits
- [ ] Add continuous integration for supported Python versions
- [ ] Add static analysis and dependency vulnerability scanning
- [ ] Expand client/server integration tests
- [ ] Improve certificate lifecycle management
- [ ] Improve private-key storage and handling
- [ ] Add structured telemetry output
- [ ] Add controlled service configuration for supported Linux environments
- [ ] Conduct an independent security review before production use

---

## Security Disclaimer

SecureVPN implements a custom encrypted tunneling protocol using established cryptographic primitives, but the security of a protocol depends on the complete implementation and protocol composition, not only on the individual algorithms.

This project has **not been independently security audited**. It should therefore be treated as a development, testing, and security-research implementation.

For real-world production VPN deployments, use established and audited VPN protocols and implementations rather than exposing this custom implementation as a production security boundary.

---

## Contributing

1. Create a feature branch.
2. Make the required changes.
3. Add or update tests for behavioral and security-sensitive changes.
4. Run the complete test suite.
5. Submit a pull request describing the change.

Security-sensitive changes should include tests for both expected behavior and relevant failure conditions.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
