# Post-Quantum Cryptography (PQC) - Backend Implementation

## Overview

The Cognitive Cyber Defense System implements **Post-Quantum Cryptography (PQC)** to provide quantum-resistant encryption for secure internal communication between microservices.

---

## Technology Stack

| Component | Implementation |
|-----------|----------------|
| **Algorithm** | ML-KEM-768 (NIST FIPS 203) |
| **Encryption** | AES-256-GCM |
| **Library** | `pqcrypto.kem.ml_kem_768` |
| **Key Derivation** | HKDF-SHA256 |
| **Service Port** | 5005 |

---

## How It Works

### 1. Key Generation
The PQC service generates an ML-KEM-768 keypair:
- **Public Key** (1184 bytes) - Shared with clients
- **Secret Key** (2400 bytes) - Kept secure on server

### 2. Key Encapsulation (Client Side)
When a client wants to establish a secure channel:
1. Receives server's public key
2. Generates a random **shared secret** (32 bytes)
3. Encapsulates it into a **ciphertext** (1088 bytes)
4. Sends ciphertext to server

### 3. Key Decapsulation (Server Side)
The server uses its secret key to:
1. Decapsulate the ciphertext
2. Extract the same 32-byte shared secret

### 4. Symmetric Encryption
Both parties now share the same secret and use it to:
1. Derive an **AES-256-GCM** key via HKDF-SHA256
2. Encrypt all subsequent data with this fast symmetric key

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/pqc/status` | GET | PQC system status |
| `/pqc/init-session` | POST | Create new PQC session |
| `/pqc/handshake` | POST | Complete key exchange |
| `/pqc/secure-data` | POST | Send encrypted data |
| `/pqc/demo` | GET | View complete flow demo |

---

## Files

```
backend/pqc-service/
├── pqc_service.py      # Flask REST API (Port 5005)
├── pqc_crypto.py       # ML-KEM-768 + AES-256-GCM implementation
├── requirements.txt    # Python dependencies
│
backend/
└── pqc-client.js       # Node.js client for other services
```

---

## Running the PQC Service

```bash
cd backend/pqc-service
pip install -r requirements.txt
python pqc_service.py
```

**Output:**
```
🔐 CCDS Post-Quantum Cryptography Service
📍 Running on: http://localhost:5005
🔬 Algorithm: ML-KEM-768 (NIST FIPS 203)
🔒 Encryption: AES-256-GCM
✅ Real PQC: Using pqcrypto.kem.ml_kem_768
```

---

## Why PQC?

Traditional encryption (RSA, ECDH) will be vulnerable once quantum computers become powerful enough. ML-KEM-768 is a **NIST-approved** post-quantum algorithm that remains secure against:
- Classical computer attacks
- Future quantum computer attacks (Shor's algorithm)

---

## Security Properties

- **Forward Secrecy**: Each session uses unique keys
- **Quantum Resistance**: ML-KEM-768 is quantum-safe
- **Authenticated Encryption**: AES-256-GCM provides confidentiality + integrity
- **Session Management**: Automatic session expiry and cleanup
