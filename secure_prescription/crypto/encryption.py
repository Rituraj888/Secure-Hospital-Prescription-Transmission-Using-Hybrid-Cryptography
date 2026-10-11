"""
AES-256-GCM Symmetric Encryption Module for Prescription Payloads.

Provides authenticated encryption ensuring Confidentiality, Integrity, and Authenticity.
Fresh 256-bit AES session keys and 96-bit nonces are generated per transmission.
"""

import json
import base64
import secrets
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_SIZE_BYTES = 32  # 256-bit key
NONCE_SIZE_BYTES = 12  # 96-bit GCM nonce
TAG_SIZE_BYTES = 16  # 128-bit authentication tag


def generate_session_key() -> bytes:
    """
    Generates a cryptographically secure random 256-bit AES session key.
    
    Returns:
        bytes: 32-byte secret key.
    """
    return secrets.token_bytes(KEY_SIZE_BYTES)


def encrypt_prescription(prescription_dict: Dict[str, Any], session_key: bytes) -> Dict[str, str]:
    """
    Encrypts prescription data using AES-256-GCM.
    
    Args:
        prescription_dict: Prescription dictionary containing patient, doctor, and medicine data.
        session_key: 32-byte AES key.
        
    Returns:
        Dict[str, str]: Base64 encoded payload components (ciphertext, nonce, tag).
    """
    if len(session_key) != KEY_SIZE_BYTES:
        raise ValueError(f"Session key must be exactly {KEY_SIZE_BYTES} bytes (256 bits).")
        
    nonce = secrets.token_bytes(NONCE_SIZE_BYTES)
    aesgcm = AESGCM(session_key)
    
    # Canonical JSON encoding for determinism
    plaintext_bytes = json.dumps(prescription_dict, sort_keys=True).encode('utf-8')
    
    # AES-GCM output in cryptography library appends the 16-byte tag to the ciphertext
    encrypted_payload = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    
    ciphertext = encrypted_payload[:-TAG_SIZE_BYTES]
    tag = encrypted_payload[-TAG_SIZE_BYTES:]
    
    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce_b64": base64.b64encode(nonce).decode('utf-8'),
        "tag_b64": base64.b64encode(tag).decode('utf-8'),
        "full_encrypted_b64": base64.b64encode(encrypted_payload).decode('utf-8')
    }


def decrypt_prescription(encrypted_dict: Dict[str, str], session_key: bytes) -> Dict[str, Any]:
    """
    Decrypts prescription payload using AES-256-GCM and verifies authentication tag.
    
    Args:
        encrypted_dict: Dict containing ciphertext_b64, nonce_b64, tag_b64 (or full_encrypted_b64).
        session_key: 32-byte AES key.
        
    Returns:
        Dict[str, Any]: Decrypted prescription dictionary.
        
    Raises:
        ValueError: If tag verification fails or payload is tampered/corrupted.
    """
    if len(session_key) != KEY_SIZE_BYTES:
        raise ValueError(f"Session key must be exactly {KEY_SIZE_BYTES} bytes (256 bits).")
        
    try:
        nonce = base64.b64decode(encrypted_dict["nonce_b64"])
        
        if "full_encrypted_b64" in encrypted_dict and encrypted_dict["full_encrypted_b64"]:
            encrypted_payload = base64.b64decode(encrypted_dict["full_encrypted_b64"])
        else:
            ciphertext = base64.b64decode(encrypted_dict["ciphertext_b64"])
            tag = base64.b64decode(encrypted_dict["tag_b64"])
            encrypted_payload = ciphertext + tag
            
        aesgcm = AESGCM(session_key)
        plaintext_bytes = aesgcm.decrypt(nonce, encrypted_payload, associated_data=None)
        return json.loads(plaintext_bytes.decode('utf-8'))
        
    except InvalidTag:
        raise ValueError("AES-GCM Authentication Failed! The ciphertext or tag has been tampered with or corrupted.")
    except Exception as e:
        raise ValueError(f"Prescription decryption error: {str(e)}")
