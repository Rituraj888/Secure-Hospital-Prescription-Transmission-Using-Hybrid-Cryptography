"""
RSA Key Utilities and Session Key Wrapping Module.

Implements RSA 3072-bit key generation, serialization, and RSA-OAEP key wrapping/unwrapping
with SHA-256 and MGF1.
"""

import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

DEFAULT_KEY_SIZE = 3072
PUBLIC_EXPONENT = 65537


def generate_rsa_key_pair(key_size: int = DEFAULT_KEY_SIZE) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a new RSA 3072-bit private/public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_private_key_pem(private_key: rsa.RSAPrivateKey) -> str:
    """
    Serializes RSA private key to PEM string (PKCS8 format).
    """
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def serialize_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """
    Serializes RSA public key to PEM string (SubjectPublicKeyInfo format).
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def load_private_key_from_pem(pem_str: str) -> rsa.RSAPrivateKey:
    """
    Loads RSA private key object from a PEM string.
    """
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def load_public_key_from_pem(pem_str: str) -> rsa.RSAPublicKey:
    """
    Loads RSA public key object from a PEM string.
    """
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )


def wrap_session_key(session_key: bytes, pharmacy_public_key: rsa.RSAPublicKey) -> str:
    """
    Encrypts (wraps) the 256-bit AES session key using Pharmacy's RSA public key with RSA-OAEP.
    
    Args:
        session_key: 32-byte AES key.
        pharmacy_public_key: Pharmacy's RSA public key object.
        
    Returns:
        str: Base64 encoded wrapped session key.
    """
    wrapped_bytes = pharmacy_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(wrapped_bytes).decode('utf-8')


def unwrap_session_key(wrapped_session_key_b64: str, pharmacy_private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypts (unwraps) the wrapped session key using Pharmacy's RSA private key with RSA-OAEP.
    
    Args:
        wrapped_session_key_b64: Base64 encoded wrapped session key.
        pharmacy_private_key: Pharmacy's RSA private key object.
        
    Returns:
        bytes: Recovered 32-byte AES session key.
        
    Raises:
        ValueError: If RSA decryption fails.
    """
    try:
        wrapped_bytes = base64.b64decode(wrapped_session_key_b64)
        session_key = pharmacy_private_key.decrypt(
            wrapped_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    except Exception as e:
        raise ValueError(f"Session key recovery failed (RSA-OAEP Decryption error): {str(e)}")
