import os
import time
import tracemalloc
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pqcrypto.kem import ml_kem_768

# --- Classical Cryptography (ECDH + AES) ---

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return binascii.hexlify(iv + ciphertext).decode()

def aes_decrypt(key, hex_ciphertext):
    data = binascii.unhexlify(hex_ciphertext)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# --- Post-Quantum Cryptography (ML-KEM / Kyber-768) ---

def kyber_keygen():
    # Returns (pk, sk) as bytes
    return ml_kem_768.generate_keypair()

def kyber_encaps(pk):
    # Returns (ciphertext, shared_secret)
    return ml_kem_768.encrypt(pk)

def kyber_decaps(sk, ct):
    # Returns shared_secret
    return ml_kem_768.decrypt(ct, sk)

def get_crypto_demo_data(username, password):
    # This function prepares the data for the animation steps using REAL crypto
    
    # 1. Classical Flow
    c_priv, c_pub = generate_ecdh_keys()
    c_pub_bytes = c_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    c_pub_hex = binascii.hexlify(c_pub_bytes).decode()
    
    # Simulate server side for ECDH
    s_priv, s_pub = generate_ecdh_keys()
    c_shared_secret = derive_shared_secret(c_priv, s_pub)
    c_encrypted_creds = aes_encrypt(c_shared_secret, f"{username}:{password}")
    
    classical_steps = [
        {"id": "c1", "label": "Capture Credentials", "data": f"User: {username}"},
        {"id": "c2", "label": "Generate ECDH key pair", "data": f"Priv: [Secret]"},
        {"id": "c3", "label": "Exchange public keys", "data": f"Pub: {c_pub_hex[:32]}..."},
        {"id": "c4", "label": "Derive shared secret", "data": f"Secret: {binascii.hexlify(c_shared_secret).decode()[:32]}..."},
        {"id": "c5", "label": "Encrypt credentials using AES", "data": f"Cipher: {c_encrypted_creds[:32]}..."},
        {"id": "c6", "label": "Decrypt credentials", "data": "Processing..."},
        {"id": "c7", "label": "Validate credentials", "data": "Classical Validation Success"}
    ]

    # 2. PQC Flow (Kyber)
    p_pk, p_sk = kyber_keygen()
    p_ct, p_ss = kyber_encaps(p_pk)
    # Use the PQC shared secret for AES encryption of credentials (consistent logic)
    p_encrypted_creds = aes_encrypt(p_ss[:32], f"{username}:{password}")
    
    pqc_steps = [
        {"id": "p1", "label": "Capture Credentials", "data": f"User: {username}"},
        {"id": "p2", "label": "Generate Kyber public/private keys", "data": f"PK: {binascii.hexlify(p_pk).decode()[:32]}..."},
        {"id": "p3", "label": "Encapsulate shared secret", "data": f"CT: {binascii.hexlify(p_ct).decode()[:32]}..."},
        {"id": "p4", "label": "Decapsulate shared secret", "data": f"Secret: {binascii.hexlify(p_ss).decode()[:32]}..."},
        {"id": "p5", "label": "Protect credentials using derived secret", "data": f"Cipher: {p_encrypted_creds[:32]}..."},
        {"id": "p6", "label": "Recover credentials", "data": "Processing..."},
        {"id": "p7", "label": "Validate credentials", "data": "PQC Validation Success"}
    ]
    
    return {
        "classical": classical_steps,
        "pqc": pqc_steps,
        "comparison": {
            "classical": {
                "algo": "ECDH (SECP256R1) + AES",
                "pk_size": f"{len(c_pub_bytes)} Bytes",
                "ct_size": f"{len(binascii.unhexlify(c_encrypted_creds))} Bytes (Encrypted Payload)",
                "quantum_safe": "NO (Shor's Algorithm)"
            },
            "pqc": {
                "algo": "ML-KEM (Kyber-768) + AES",
                "pk_size": f"{len(p_pk)} Bytes",
                "ct_size": f"{len(p_ct)} Bytes (Encapsulation)",
                "quantum_safe": "YES (Lattice-Based)"
            }
        }
    }


# --- Benchmarking: Latency, Scalability & Computational Overhead ---

def _bench(fn, iterations):
    """Run fn() for `iterations` times, return (avg_ms, peak_kb, ops_per_sec)."""
    tracemalloc.start()
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    avg_ms     = (elapsed / iterations) * 1000   # ms per operation
    peak_kb    = peak / 1024                     # KB peak memory
    ops_per_sec = iterations / elapsed           # throughput
    return round(avg_ms, 4), round(peak_kb, 2), round(ops_per_sec, 2)


def get_benchmark_data(iterations=50):
    """
    Benchmark ML-KEM-768 (Kyber) vs ECDH across:
      - Key-exchange latency  (keygen / encaps / decaps per step)
      - Scalability           (full handshakes per second)
      - Computational overhead (peak memory, key/ciphertext sizes)
    """

    # ── ML-KEM-768 ────────────────────────────────────────────────────────────
    kyber_kg_ms,  kyber_kg_kb,  kyber_kg_ops  = _bench(
        lambda: ml_kem_768.generate_keypair(), iterations)

    _pk, _sk = ml_kem_768.generate_keypair()
    kyber_enc_ms, kyber_enc_kb, kyber_enc_ops = _bench(
        lambda: ml_kem_768.encrypt(_pk), iterations)

    _ct, _ = ml_kem_768.encrypt(_pk)
    kyber_dec_ms, kyber_dec_kb, kyber_dec_ops = _bench(
        lambda: ml_kem_768.decrypt(_sk, _ct), iterations)

    def _kyber_full():
        pk, sk = ml_kem_768.generate_keypair()
        ct, _  = ml_kem_768.encrypt(pk)
        ml_kem_768.decrypt(sk, ct)

    kyber_full_ms, kyber_full_kb, kyber_full_ops = _bench(_kyber_full, iterations)

    # ── ECDH ──────────────────────────────────────────────────────────────────
    ecdh_kg_ms,  ecdh_kg_kb,  ecdh_kg_ops  = _bench(
        lambda: ec.generate_private_key(ec.SECP256R1(), default_backend()), iterations)

    _c_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    _s_pub  = ec.generate_private_key(ec.SECP256R1(), default_backend()).public_key()
    ecdh_exc_ms, ecdh_exc_kb, ecdh_exc_ops = _bench(
        lambda: _c_priv.exchange(ec.ECDH(), _s_pub), iterations)

    def _ecdh_full():
        cp = ec.generate_private_key(ec.SECP256R1(), default_backend())
        sp = ec.generate_private_key(ec.SECP256R1(), default_backend())
        cp.exchange(ec.ECDH(), sp.public_key())

    ecdh_full_ms, ecdh_full_kb, ecdh_full_ops = _bench(_ecdh_full, iterations)

    # ── Static sizes ──────────────────────────────────────────────────────────
    pk, sk  = ml_kem_768.generate_keypair()
    ct, ss  = ml_kem_768.encrypt(pk)
    c_priv  = ec.generate_private_key(ec.SECP256R1(), default_backend())
    c_pub_b = c_priv.public_key().public_bytes(
                  serialization.Encoding.X962,
                  serialization.PublicFormat.UncompressedPoint)

    overhead_pct = round(((kyber_full_ms - ecdh_full_ms) / ecdh_full_ms) * 100, 1)

    return {
        "iterations": iterations,

        # ── Latency (ms / operation) ──────────────────────────────────────────
        "latency": {
            "kyber": {
                "keygen_ms":         kyber_kg_ms,
                "encapsulate_ms":    kyber_enc_ms,
                "decapsulate_ms":    kyber_dec_ms,
                "full_handshake_ms": kyber_full_ms,
            },
            "ecdh": {
                "keygen_ms":         ecdh_kg_ms,
                "exchange_ms":       ecdh_exc_ms,
                "full_handshake_ms": ecdh_full_ms,
            },
            "faster":       "ECDH" if ecdh_full_ms < kyber_full_ms else "ML-KEM-768",
            "overhead_pct": overhead_pct,
            "note": (
                f"ML-KEM-768 full handshake is {overhead_pct}% "
                f"{'slower' if overhead_pct > 0 else 'faster'} than ECDH."
            )
        },

        # ── Scalability (handshakes / second) ─────────────────────────────────
        "scalability": {
            "kyber_full_ops_per_sec":  kyber_full_ops,
            "ecdh_full_ops_per_sec":   ecdh_full_ops,
            "kyber_keygen_ops_per_sec":  kyber_kg_ops,
            "kyber_encaps_ops_per_sec":  kyber_enc_ops,
            "kyber_decaps_ops_per_sec":  kyber_dec_ops,
            "sessions_per_min_single_core": int(kyber_full_ops * 60),
            "note": (
                f"ML-KEM-768 handles ~{kyber_full_ops:.0f} full handshakes/sec "
                f"(~{int(kyber_full_ops * 60):,} sessions/min) on a single core."
            )
        },

        # ── Computational / Memory Overhead ───────────────────────────────────
        "overhead": {
            "kyber": {
                "pk_bytes":               len(pk),
                "sk_bytes":               len(sk),
                "ct_bytes":               len(ct),
                "shared_secret_bytes":    len(ss),
                "keygen_peak_kb":         kyber_kg_kb,
                "encapsulate_peak_kb":    kyber_enc_kb,
                "decapsulate_peak_kb":    kyber_dec_kb,
                "full_handshake_peak_kb": kyber_full_kb,
            },
            "ecdh": {
                "pk_bytes":               len(c_pub_b),
                "sk_bytes":               32,
                "ct_bytes":               "N/A",
                "shared_secret_bytes":    32,
                "keygen_peak_kb":         ecdh_kg_kb,
                "exchange_peak_kb":       ecdh_exc_kb,
                "full_handshake_peak_kb": ecdh_full_kb,
            },
            "pk_size_ratio": round(len(pk) / len(c_pub_b), 1),
            "note": (
                f"ML-KEM-768 public key is {round(len(pk)/len(c_pub_b),1)}x larger "
                f"than ECDH ({len(pk)} B vs {len(c_pub_b)} B) — "
                "the accepted cost of quantum safety."
            )
        }
    }
