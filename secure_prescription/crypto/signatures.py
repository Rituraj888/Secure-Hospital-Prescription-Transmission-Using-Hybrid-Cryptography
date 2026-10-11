"""
Digital Signatures Module using RSA-PSS and SHA-256.

Ensures Authenticity, Integrity, and Non-repudiation of hospital prescriptions.
"""

import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def _canonicalize_prescription(prescription_dict: dict) -> bytes:
    """
    Creates a deterministic, canonical UTF-8 JSON byte representation of prescription fields.
    """
    return json.dumps(prescription_dict, sort_keys=True).encode('utf-8')


def sign_prescription(prescription_dict: dict, doctor_private_key: rsa.RSAPrivateKey) -> str:
    """
    Signs the prescription using the Doctor's RSA Private Signing Key with RSA-PSS and SHA-256.
    
    Args:
        prescription_dict: The prescription dictionary.
        doctor_private_key: Doctor's RSA private signing key.
        
    Returns:
        str: Base64 encoded digital signature.
    """
    canonical_bytes = _canonicalize_prescription(prescription_dict)
    
    signature_bytes = doctor_private_key.sign(
        canonical_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature_bytes).decode('utf-8')


def verify_signature(prescription_dict: dict, signature_b64: str, doctor_public_key: rsa.RSAPublicKey) -> bool:
    """
    Verifies the Doctor's digital signature using the Doctor's RSA Public Signing Key.
    
    Args:
        prescription_dict: The prescription dictionary.
        signature_b64: Base64 encoded digital signature.
        doctor_public_key: Doctor's RSA public signing key.
        
    Returns:
        bool: True if valid signature, False otherwise.
    """
    try:
        canonical_bytes = _canonicalize_prescription(prescription_dict)
        signature_bytes = base64.b64decode(signature_b64)
        
        doctor_public_key.verify(
            signature_bytes,
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False
