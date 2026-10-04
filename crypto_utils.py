"""
Secure LAN Chat & File Transfer - Cryptography & Protocol Utilities
Provides:
- AES-256-GCM Transport Encryption (framing over sockets)
- X25519 ECDH End-to-End Encryption (E2EE) for private messages and files
- PBKDF2-HMAC-SHA256 Key Derivation
- Streaming SHA-256 integrity verification
- File path sanitization against directory traversal
"""

import os
import sys
import json
import base64
import hashlib
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

# Shared salt for transport key derivation
DEFAULT_SALT = b"lan-chat-fixed-salt-v2"
E2EE_SALT = b"lan-chat-e2ee-salt-v2"
CHUNK_SIZE = 64 * 1024  # 64 KB per chunk


def derive_transport_key(passphrase: str, salt: bytes = DEFAULT_SALT) -> bytes:
    """Derive 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000
    )
    return kdf.derive(passphrase.encode("utf-8"))


# --- End-to-End Encryption (E2EE) with X25519 & HKDF ---

def generate_ecdh_keypair() -> Tuple[x25519.X25519PrivateKey, str]:
    """Generate an X25519 private key and return (private_key, public_key_hex)."""
    priv_key = x25519.X25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    return priv_key, pub_bytes.hex()


def derive_e2ee_shared_key(my_private_key: x25519.X25519PrivateKey, peer_public_key_hex: str) -> bytes:
    """Perform ECDH key exchange and derive a 256-bit symmetric key using HKDF."""
    peer_pub_bytes = bytes.fromhex(peer_public_key_hex)
    peer_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    raw_shared_secret = my_private_key.exchange(peer_pub_key)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=E2EE_SALT,
        info=b"lan-chat-e2ee-session-key",
    )
    return hkdf.derive(raw_shared_secret)


def e2ee_encrypt_payload(shared_key: bytes, plaintext: str) -> str:
    """Encrypt a private text message with the peer's E2EE key."""
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = nonce + ct
    return base64.b64encode(payload).decode("ascii")


def e2ee_decrypt_payload(shared_key: bytes, b64_ciphertext: str) -> Optional[str]:
    """Decrypt an E2EE encrypted text message."""
    try:
        raw = base64.b64decode(b64_ciphertext.encode("ascii"))
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(shared_key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None


def e2ee_encrypt_bytes(shared_key: bytes, data: bytes) -> bytes:
    """Encrypt raw bytes using E2EE key."""
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct


def e2ee_decrypt_bytes(shared_key: bytes, encrypted_data: bytes) -> Optional[bytes]:
    """Decrypt raw bytes using E2EE key."""
    try:
        nonce, ct = encrypted_data[:12], encrypted_data[12:]
        aesgcm = AESGCM(shared_key)
        return aesgcm.decrypt(nonce, ct, None)
    except Exception:
        return None


# --- TCP Framing & Transport AES-256-GCM ---

def recv_exact(conn, n: int) -> Optional[bytes]:
    """Receive exactly n bytes from a socket, or return None on disconnect."""
    data = bytearray()
    while len(data) < n:
        try:
            chunk = conn.recv(min(4096, n - len(data)))
        except (OSError, ConnectionResetError):
            return None
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def send_encrypted_frame(conn, plaintext_bytes: bytes, aesgcm_cipher: AESGCM) -> bool:
    """Encrypt and send a framed payload: [4-byte length][12-byte nonce][ciphertext + tag]."""
    try:
        nonce = os.urandom(12)
        ct = aesgcm_cipher.encrypt(nonce, plaintext_bytes, None)
        payload = nonce + ct
        hdr = len(payload).to_bytes(4, "big")
        conn.sendall(hdr + payload)
        return True
    except (OSError, BrokenPipeError, ConnectionResetError):
        return False


def recv_encrypted_frame(conn, aesgcm_cipher: AESGCM) -> Optional[bytes]:
    """Receive and decrypt a single frame from the socket."""
    hdr = recv_exact(conn, 4)
    if hdr is None:
        return None
    length = int.from_bytes(hdr, "big")
    if length <= 12 or length > 50 * 1024 * 1024:  # Max 50 MB sanity check
        return None
    payload = recv_exact(conn, length)
    if payload is None:
        return None
    nonce, ct = payload[:12], payload[12:]
    try:
        return aesgcm_cipher.decrypt(nonce, ct, None)
    except Exception:
        return None  # Decryption failure / tampering


def send_json_packet(conn, packet_dict: Dict[str, Any], aesgcm_cipher: AESGCM) -> bool:
    """Send a dictionary as an encrypted JSON frame."""
    data = json.dumps(packet_dict, ensure_ascii=False).encode("utf-8")
    return send_encrypted_frame(conn, data, aesgcm_cipher)


def recv_json_packet(conn, aesgcm_cipher: AESGCM) -> Optional[Dict[str, Any]]:
    """Receive and parse an encrypted JSON frame into a dictionary."""
    data = recv_encrypted_frame(conn, aesgcm_cipher)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


# --- File Utilities & Streaming SHA-256 ---

def sanitize_filename(filename: str) -> str:
    """Prevent directory traversal and invalid filename characters."""
    base = os.path.basename(filename).strip()
    # Strip any directory separators that might have slipped through
    base = base.replace("\\", "_").replace("/", "_").replace("..", "_")
    if not base:
        base = "downloaded_file"
    return base


def get_unique_filepath(directory: str, filename: str) -> str:
    """Return a unique filepath in the directory, appending (1), (2), etc. if needed."""
    os.makedirs(directory, exist_ok=True)
    clean_name = sanitize_filename(filename)
    target = os.path.join(directory, clean_name)
    if not os.path.exists(target):
        return target
    
    name, ext = os.path.splitext(clean_name)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{name} ({counter}){ext}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def compute_file_sha256(filepath: str) -> Tuple[str, int]:
    """Compute SHA-256 and size of a file using streaming chunks (low RAM usage)."""
    hasher = hashlib.sha256()
    total_size = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            total_size += len(chunk)
    return hasher.hexdigest(), total_size
