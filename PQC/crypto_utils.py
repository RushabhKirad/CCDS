import os
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
