"""
Key Management Module for RSA Public/Private Key Lifecycle, Expiration, Revocation, and Rotation.

Implements key storage, verification flow, metadata tracking, key revocation, and key rotation.
"""

import os
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.rsa_utils import (
    generate_rsa_key_pair,
    serialize_private_key_pem,
    serialize_public_key_pem,
    load_private_key_from_pem,
    load_public_key_from_pem
)

# Paths relative to project root
BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"
DATA_DIR = BASE_DIR / "data"
DOCTOR_KEYS_DIR = KEYS_DIR / "doctor"
PHARMACY_KEYS_DIR = KEYS_DIR / "pharmacy"
DOCTORS_FILE = DATA_DIR / "doctors.json"
PHARMACIES_FILE = DATA_DIR / "pharmacies.json"
AUDIT_LOG_FILE = DATA_DIR / "audit_log.json"


def init_environment() -> None:
    """
    Creates necessary directories and initializes default synthetic records and RSA key pairs.
    """
    DOCTOR_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PHARMACY_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not DOCTORS_FILE.exists():
        initial_doctors = {
            "DOC102": {
                "doctor_id": "DOC102",
                "name": "Dr. Sarah Jenkins",
                "department": "Cardiology",
                "active_key_id": "DOC102-SIGN-001"
            }
        }
        with open(DOCTORS_FILE, 'w', encoding='utf-8') as f:
            json.dump(initial_doctors, f, indent=4)

    if not PHARMACIES_FILE.exists():
        initial_pharmacies = {
            "PHARM001": {
                "pharmacy_id": "PHARM001",
                "name": "St. Jude Central Hospital Pharmacy",
                "location": "Building A, Floor 1",
                "active_key_id": "PHARM001-ENC-001"
            }
        }
        with open(PHARMACIES_FILE, 'w', encoding='utf-8') as f:
            json.dump(initial_pharmacies, f, indent=4)

    if not AUDIT_LOG_FILE.exists():
        with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4)

    # Initialize default keys if they do not exist
    _ensure_key_exists("DOC102", "DOC102-SIGN-001", "doctor", "SIGNING")
    _ensure_key_exists("PHARM001", "PHARM001-ENC-001", "pharmacy", "ENCRYPTION")


def _ensure_key_exists(owner_id: str, key_id: str, owner_type: str, purpose: str) -> None:
    target_dir = DOCTOR_KEYS_DIR if owner_type == "doctor" else PHARMACY_KEYS_DIR
    meta_file = target_dir / f"{key_id}_meta.json"
    if not meta_file.exists():
        create_and_store_key_pair(owner_id=owner_id, owner_type=owner_type, purpose=purpose, key_id=key_id)


def create_and_store_key_pair(
    owner_id: str,
    owner_type: str,
    purpose: str,
    key_id: Optional[str] = None,
    validity_days: int = 30
) -> Dict[str, Any]:
    """
    Generates an RSA key pair, saves private/public PEM files and metadata JSON.
    """
    target_dir = DOCTOR_KEYS_DIR if owner_type == "doctor" else PHARMACY_KEYS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    if not key_id:
        existing_keys = [f for f in target_dir.glob("*_meta.json")]
        count = len(existing_keys) + 1
        prefix = "SIGN" if purpose.upper() == "SIGNING" else "ENC"
        key_id = f"{owner_id}-{prefix}-{count:03d}"

    private_key, public_key = generate_rsa_key_pair()
    priv_pem = serialize_private_key_pem(private_key)
    pub_pem = serialize_public_key_pem(public_key)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=validity_days)

    meta = {
        "key_id": key_id,
        "owner_id": owner_id,
        "owner_type": owner_type,
        "purpose": purpose,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "status": "ACTIVE"
    }

    # Save private key (kept safe, never logged/printed)
    priv_path = target_dir / f"{key_id}_private.pem"
    with open(priv_path, 'w', encoding='utf-8') as f:
        f.write(priv_pem)

    # Save public key
    pub_path = target_dir / f"{key_id}_public.pem"
    with open(pub_path, 'w', encoding='utf-8') as f:
        f.write(pub_pem)

    # Save metadata
    meta_path = target_dir / f"{key_id}_meta.json"
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=4)

    return meta


def get_key_metadata(key_id: str) -> Optional[Dict[str, Any]]:
    """
    Finds and returns key metadata dict for a given key_id.
    """
    for folder in [DOCTOR_KEYS_DIR, PHARMACY_KEYS_DIR]:
        meta_file = folder / f"{key_id}_meta.json"
        if meta_file.exists():
            with open(meta_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    return None


def update_key_metadata(key_id: str, new_meta: Dict[str, Any]) -> bool:
    """
    Updates stored metadata JSON for key_id.
    """
    for folder in [DOCTOR_KEYS_DIR, PHARMACY_KEYS_DIR]:
        meta_file = folder / f"{key_id}_meta.json"
        if meta_file.exists():
            with open(meta_file, 'w', encoding='utf-8') as f:
                json.dump(new_meta, f, indent=4)
            return True
    return False


def check_key_status(key_id: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Evaluates key validity following the exact flowchart requirements:
      Does key exist? -> Is key revoked? -> Is key expired? -> Is key active? -> Accept key
      
    Returns:
        Tuple[bool, str, Optional[dict]]: (is_valid, reason_code, metadata)
    """
    meta = get_key_metadata(key_id)
    if not meta:
        return False, f"KEY_NOT_FOUND: Key ID '{key_id}' does not exist in registry.", None

    status = meta.get("status", "UNKNOWN").upper()
    if status == "REVOKED":
        return False, f"REVOKED: Key '{key_id}' has been explicitly revoked by system administrator.", meta

    # Check timestamp expiration
    expires_at_str = meta.get("expires_at")
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        now = datetime.now(timezone.utc)
        if now > expires_at:
            # Auto update status to EXPIRED if past expiry date
            if status != "EXPIRED":
                meta["status"] = "EXPIRED"
                update_key_metadata(key_id, meta)
            return False, f"EXPIRED: Key '{key_id}' expired on {expires_at_str}.", meta

    if status == "EXPIRED":
        return False, f"EXPIRED: Key '{key_id}' has expired status.", meta

    if status != "ACTIVE":
        return False, f"INACTIVE: Key '{key_id}' status is '{status}'.", meta

    return True, "ACTIVE: Key is valid and active.", meta


def load_doctor_public_key(key_id: str) -> rsa.RSAPublicKey:
    """
    Loads Doctor's RSA Public Key object by key_id.
    """
    meta_path = DOCTOR_KEYS_DIR / f"{key_id}_meta.json"
    pub_path = DOCTOR_KEYS_DIR / f"{key_id}_public.pem"
    if not pub_path.exists():
        raise FileNotFoundError(f"Public key file for '{key_id}' not found.")
    with open(pub_path, 'r', encoding='utf-8') as f:
        pem_data = f.read()
    return load_public_key_from_pem(pem_data)


def load_doctor_private_key(key_id: str) -> rsa.RSAPrivateKey:
    """
    Loads Doctor's RSA Private Key object by key_id (Used only internally by Doctor module).
    """
    priv_path = DOCTOR_KEYS_DIR / f"{key_id}_private.pem"
    if not priv_path.exists():
        raise FileNotFoundError(f"Private key file for '{key_id}' not found.")
    with open(priv_path, 'r', encoding='utf-8') as f:
        pem_data = f.read()
    return load_private_key_from_pem(pem_data)


def load_pharmacy_public_key(key_id: str) -> rsa.RSAPublicKey:
    """
    Loads Pharmacy's RSA Public Key object by key_id.
    """
    pub_path = PHARMACY_KEYS_DIR / f"{key_id}_public.pem"
    if not pub_path.exists():
        raise FileNotFoundError(f"Pharmacy Public key file for '{key_id}' not found.")
    with open(pub_path, 'r', encoding='utf-8') as f:
        pem_data = f.read()
    return load_public_key_from_pem(pem_data)


def load_pharmacy_private_key(key_id: str) -> rsa.RSAPrivateKey:
    """
    Loads Pharmacy's RSA Private Key object by key_id (Used only internally by Pharmacy module).
    """
    priv_path = PHARMACY_KEYS_DIR / f"{key_id}_private.pem"
    if not priv_path.exists():
        raise FileNotFoundError(f"Pharmacy Private key file for '{key_id}' not found.")
    with open(priv_path, 'r', encoding='utf-8') as f:
        pem_data = f.read()
    return load_private_key_from_pem(pem_data)


def expire_key(key_id: str) -> bool:
    """
    Manually sets a key's status to EXPIRED.
    """
    meta = get_key_metadata(key_id)
    if meta:
        meta["status"] = "EXPIRED"
        return update_key_metadata(key_id, meta)
    return False


def revoke_key(key_id: str) -> bool:
    """
    Manually revokes a key.
    """
    meta = get_key_metadata(key_id)
    if meta:
        meta["status"] = "REVOKED"
        return update_key_metadata(key_id, meta)
    return False


def activate_key(key_id: str) -> bool:
    """
    Resets key status to ACTIVE (used for Reset Test simulation).
    """
    meta = get_key_metadata(key_id)
    if meta:
        meta["status"] = "ACTIVE"
        now = datetime.now(timezone.utc)
        meta["expires_at"] = (now + timedelta(days=30)).isoformat()
        return update_key_metadata(key_id, meta)
    return False


def rotate_key(owner_id: str, owner_type: str, purpose: str) -> Dict[str, Any]:
    """
    Rotates keys for an owner: expires all old active keys and creates a fresh active key pair.
    """
    target_dir = DOCTOR_KEYS_DIR if owner_type == "doctor" else PHARMACY_KEYS_DIR
    # Expire existing keys for this owner
    for meta_file in target_dir.glob("*_meta.json"):
        with open(meta_file, 'r', encoding='utf-8') as f:
            m = json.load(f)
        if m.get("owner_id") == owner_id and m.get("purpose") == purpose and m.get("status") == "ACTIVE":
            m["status"] = "EXPIRED"
            with open(meta_file, 'w', encoding='utf-8') as fw:
                json.dump(m, fw, indent=4)

    new_meta = create_and_store_key_pair(owner_id=owner_id, owner_type=owner_type, purpose=purpose)
    
    # Update doctor/pharmacy record active_key_id
    if owner_type == "doctor" and DOCTORS_FILE.exists():
        with open(DOCTORS_FILE, 'r', encoding='utf-8') as f:
            docs = json.load(f)
        if owner_id in docs:
            docs[owner_id]["active_key_id"] = new_meta["key_id"]
            with open(DOCTORS_FILE, 'w', encoding='utf-8') as f:
                json.dump(docs, f, indent=4)
    elif owner_type == "pharmacy" and PHARMACIES_FILE.exists():
        with open(PHARMACIES_FILE, 'r', encoding='utf-8') as f:
            pharms = json.load(f)
        if owner_id in pharms:
            pharms[owner_id]["active_key_id"] = new_meta["key_id"]
            with open(PHARMACIES_FILE, 'w', encoding='utf-8') as f:
                json.dump(pharms, f, indent=4)

    return new_meta


def list_all_keys() -> List[Dict[str, Any]]:
    """
    Returns list of metadata dictionaries for all registered doctor and pharmacy keys.
    """
    keys_list = []
    for folder in [DOCTOR_KEYS_DIR, PHARMACY_KEYS_DIR]:
        for meta_file in folder.glob("*_meta.json"):
            try:
                with open(meta_file, 'r', encoding='utf-8') as f:
                    keys_list.append(json.load(f))
            except Exception:
                pass
    keys_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return keys_list
