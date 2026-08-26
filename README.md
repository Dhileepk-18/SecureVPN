# SecureVPN — Production-Grade Ephemeral Encrypted Tunnel

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security Suite](https://img.shields.io/badge/tests-24%20passed-success.svg)](./tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SecureVPN is a multi-threaded, authenticated, encrypted TCP tunneling application written in Python. It implements modern, enterprise-grade cryptographic standards matching industry specifications like **TLS 1.3, WireGuard, and IPsec (RFC 4303)**.

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
