"""
Secure Hospital Prescription Transmission Using Hybrid Cryptography
Streamlit Web Application for Educational Demonstration & Final Year Project.
"""

import json
import base64
import secrets
from datetime import datetime, timezone
from pathlib import Path
import streamlit as st
import pandas as pd

from crypto.encryption import generate_session_key, encrypt_prescription, decrypt_prescription
from crypto.rsa_utils import wrap_session_key, unwrap_session_key
from crypto.signatures import sign_prescription, verify_signature
from crypto.key_manager import (
    init_environment, check_key_status, load_doctor_private_key, load_doctor_public_key,
    load_pharmacy_private_key, load_pharmacy_public_key, get_key_metadata,
    expire_key, revoke_key, activate_key, rotate_key, list_all_keys, AUDIT_LOG_FILE
)

# Page Setup
st.set_page_config(
    page_title="Secure Hospital Prescription Transmission",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_environment()

BASE_DIR = Path(__file__).resolve().parent
BANNER_PATH = BASE_DIR / "assets" / "hospital_crypto_banner.jpg"
DIAGRAM_PATH = BASE_DIR / "assets" / "hybrid_crypto_diagram.jpg"


def log_audit_event(event: str, actor: str, status: str, details: str):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = {"timestamp": timestamp, "event": event, "actor": actor, "status": status, "details": details}
    logs = []
    if AUDIT_LOG_FILE.exists():
        try:
            with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.insert(0, entry)
    with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=4)


def load_audit_logs():
    if AUDIT_LOG_FILE.exists():
        try:
            with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []


# High-contrast, theme-adaptive CSS styling
st.markdown("""
    <style>
    .main-header { font-size: 2.2rem; font-weight: 800; color: #0f172a; text-align: center; margin-bottom: 0.2rem; }
    .sub-header { font-size: 1.1rem; color: #334155; text-align: center; margin-bottom: 1.2rem; }
    .warning-banner { background-color: #fffbe6; border-left: 5px solid #d97706; padding: 0.85rem 1rem; border-radius: 6px; color: #78350f; font-weight: 600; margin-bottom: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    
    /* Sleek high-contrast glassmorphism metric cards */
    .metric-card-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 0.85rem 0.5rem;
        text-align: center;
        color: #ffffff !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        transition: transform 0.2s ease;
    }
    .metric-card-title {
        font-size: 0.85rem;
        font-weight: 700;
        color: #94a3b8;
        margin-bottom: 0.3rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .metric-card-badge-pass {
        font-size: 1.1rem;
        font-weight: bold;
        color: #10b981;
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 0.2rem 0.6rem;
        border-radius: 20px;
        display: inline-block;
    }
    .metric-card-badge-fail {
        font-size: 1.1rem;
        font-weight: bold;
        color: #ef4444;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 0.2rem 0.6rem;
        border-radius: 20px;
        display: inline-block;
    }
    </style>
""", unsafe_allow_html=True)

if "transmission_package" not in st.session_state:
    st.session_state["transmission_package"] = None

if "last_verification_result" not in st.session_state:
    st.session_state["last_verification_result"] = {
        "confidentiality": True, "integrity": True, "authentication": True,
        "key_exchange": True, "tamper_detection": True, "key_expiration": True, "key_revocation": True
    }

# Top Visual Hero Banner Image
if BANNER_PATH.exists():
    st.image(str(BANNER_PATH), use_container_width=True)

st.markdown("<div class='warning-banner'>⚠️ <strong>Educational Prototype Notice:</strong> Synthetic patient data only. Do not enter real patient information or personal health data.</div>", unsafe_allow_html=True)


# Render High-Contrast Futuristic Security Metrics Dashboard
def render_security_dashboard():
    v = st.session_state["last_verification_result"]
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
    
    metrics = [
        ("🔒 Confidential", v['confidentiality'], col1),
        ("🛡️ Integrity", v['integrity'], col2),
        ("✍️ Authenticated", v['authentication'], col3),
        ("🔑 Key Exchange", v['key_exchange'], col4),
        ("🚨 Tamper Detect", v['tamper_detection'], col5),
        ("⏰ Key Expiry", v['key_expiration'], col6),
        ("🚫 Key Revocation", v['key_revocation'], col7),
    ]
    
    for title, is_pass, col in metrics:
        badge_html = f"<span class='metric-card-badge-pass'>✓ VERIFIED</span>" if is_pass else f"<span class='metric-card-badge-fail'>✗ FAILED</span>"
        with col:
            st.markdown(f"""
            <div class='metric-card-box'>
                <div class='metric-card-title'>{title}</div>
                {badge_html}
            </div>
            """, unsafe_allow_html=True)

render_security_dashboard()
st.divider()

# Sidebar Navigation
st.sidebar.title("Navigation & Controls")
menu = st.sidebar.radio(
    "Select System Page:",
    [
        "👨‍⚕️ Doctor System",
        "🏥 Pharmacy System",
        "🔑 Key Management",
        "🧪 Security Testing & Attack Simulation",
        "📜 Audit Log",
        "📘 How Hybrid Cryptography Works",
        "🎓 Security Concepts & Defense"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("**System Specifications**\n- **Cipher**: AES-256-GCM\n- **Key Wrapping**: RSA-3072 OAEP\n- **Signatures**: RSA-PSS (SHA-256)\n- **Padding**: MGF1 SHA-256")


# ==========================================
# PAGE 1: DOCTOR SYSTEM
# ==========================================
if menu == "👨‍⚕️ Doctor System":
    st.header("👨‍⚕️ Doctor System — Prescription Transmission")
    st.write("Construct and digitally sign a synthetic prescription for encrypted transmission to the Pharmacy.")

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("1. Prescription Form Input")
        doctor_id = st.selectbox("Doctor ID", ["DOC102"], index=0)
        patient_id = st.text_input("Patient ID", value="PAT501")
        medicine = st.selectbox("Medicine", ["Amoxicillin", "Ciprofloxacin", "Metformin", "Lisinopril", "Atorvastatin"], index=0)
        dosage = st.text_input("Dosage", value="500 mg")
        frequency = st.selectbox("Frequency", ["1 time/day", "2 times/day", "3 times/day", "Every 6 hours"], index=1)
        duration = st.selectbox("Duration", ["3 days", "5 days", "7 days", "10 days", "14 days"], index=1)
        pharmacy_id = st.selectbox("Target Pharmacy ID", ["PHARM001"], index=0)

        send_btn = st.button("🚀 Send Prescription Securely", type="primary", use_container_width=True)

    with col_right:
        st.subheader("2. Secure Transmission Workflow Execution")
        if send_btn:
            doc_keys = list_all_keys()
            doc_meta = next((k for k in doc_keys if k["owner_id"] == doctor_id and k["purpose"] == "SIGNING" and k["status"] == "ACTIVE"), None)
            pharm_meta = next((k for k in doc_keys if k["owner_id"] == pharmacy_id and k["purpose"] == "ENCRYPTION" and k["status"] == "ACTIVE"), None)

            if not doc_meta or not pharm_meta:
                st.error("❌ Error: Missing active keys for Doctor or Pharmacy.")
                st.stop()

            doc_key_id = doc_meta["key_id"]
            pharm_key_id = pharm_meta["key_id"]

            st.markdown("#### Step 1 — Prescription Creation")
            rx_id = f"RX-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
            prescription_data = {
                "prescription_id": rx_id, "doctor_id": doctor_id, "patient_id": patient_id,
                "medicine": medicine, "dosage": dosage, "frequency": frequency, "duration": duration,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            }
            st.success(f"✓ Prescription created (ID: `{rx_id}`)")
            log_audit_event("Prescription Created", doctor_id, "SUCCESS", f"Rx ID: {rx_id}")

            st.markdown("#### Step 2 — Session Key Generation")
            session_key = generate_session_key()
            st.code("Generating session key...\n✓ Session key generated\n\nSession Key : ******************************** (Hidden 256-bit AES)\nAlgorithm   : AES-256-GCM\nStatus      : Generated", language="text")

            st.markdown("#### Step 3 — Prescription Encryption")
            encrypted_dict = encrypt_prescription(prescription_data, session_key)
            st.code(f"Encrypting prescription...\n✓ Encryption successful\n\nAlgorithm          : AES-256-GCM\nNonce (IV)         : {encrypted_dict['nonce_b64']}\nAuthentication Tag : Generated", language="text")

            st.markdown("#### Step 4 — Digital Signature Generation")
            doctor_priv_key = load_doctor_private_key(doc_key_id)
            signature_b64 = sign_prescription(prescription_data, doctor_priv_key)
            st.code(f"Generating digital signature...\n✓ Signature generated\n\nSigning Algorithm : RSA-PSS + SHA-256\nSigner            : {doctor_id}", language="text")

            st.markdown("#### Step 5 — Protect Session Key")
            pharm_pub_key = load_pharmacy_public_key(pharm_key_id)
            wrapped_session_key_b64 = wrap_session_key(session_key, pharm_pub_key)
            st.code("Protecting session key using RSA...\n✓ Key protection successful\n\nAlgorithm : RSA-OAEP (SHA-256 / MGF1)", language="text")

            package = {
                "prescription_id": rx_id, "doctor_id": doctor_id, "pharmacy_id": pharmacy_id,
                "prescription_data": prescription_data, "encrypted_prescription": encrypted_dict["ciphertext_b64"],
                "nonce": encrypted_dict["nonce_b64"], "tag": encrypted_dict["tag_b64"],
                "full_encrypted_b64": encrypted_dict["full_encrypted_b64"],
                "wrapped_session_key": wrapped_session_key_b64, "signature": signature_b64,
                "signature_algorithm": "RSA-PSS-SHA256", "encryption_algorithm": "AES-256-GCM",
                "key_id": doc_key_id, "pharmacy_key_id": pharm_key_id,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "is_tampered": False
            }
            st.session_state["transmission_package"] = package
            st.success("🎉 Secure Package transmitted to Pharmacy System!")
            log_audit_event("Package Transmitted", doctor_id, "SUCCESS", f"Package {rx_id} sent")
        else:
            st.info("Fill out the form and click **Send Prescription Securely** to execute the cryptographic workflow.")


# ==========================================
# PAGE 2: PHARMACY SYSTEM
# ==========================================
elif menu == "🏥 Pharmacy System":
    st.header("🏥 Pharmacy System — Prescription Reception & Verification")
    package = st.session_state.get("transmission_package")

    if not package:
        st.warning("⚠️ No prescription package received. Please send one from the **Doctor System** page.")
    else:
        st.subheader("📬 Prescription Package Received")
        with st.expander("📦 View Received Encrypted Package Payload", expanded=False):
            st.json({
                "prescription_id": package["prescription_id"],
                "doctor_id": package["doctor_id"],
                "pharmacy_id": package["pharmacy_id"],
                "encrypted_prescription": package["encrypted_prescription"][:40] + "...",
                "nonce": package["nonce"],
                "tag": package["tag"],
                "wrapped_session_key": package["wrapped_session_key"][:40] + "...",
                "signature": package["signature"][:40] + "...",
                "signature_algorithm": package["signature_algorithm"],
                "encryption_algorithm": package["encryption_algorithm"],
                "key_id": package["key_id"],
                "pharmacy_key_id": package["pharmacy_key_id"],
                "timestamp": package["timestamp"]
            })

        st.markdown("---")
        st.subheader("🔍 Verification & Decryption Sequence")

        # Step 1: Doctor Authentication
        st.markdown("#### 1. Doctor Authentication & Key Status Check")
        doc_key_valid, doc_reason, doc_meta = check_key_status(package["key_id"])

        if doc_key_valid:
            st.success(f"Doctor Authentication: **✓ VERIFIED** (Doctor Key: `{package['key_id']}` ACTIVE)")
            log_audit_event("Doctor Authentication", package["pharmacy_id"], "VERIFIED", doc_reason)
        else:
            st.error(f"Doctor Authentication: **✗ FAILED** ({doc_reason})")
            st.warning("⛔ Processing Halted: Transmission rejected due to unauthenticated or expired Doctor key.")
            log_audit_event("Doctor Authentication", package["pharmacy_id"], "FAILED", doc_reason)
            st.session_state["last_verification_result"]["authentication"] = False
            st.session_state["last_verification_result"]["key_expiration"] = False if "EXPIRED" in doc_reason else True
            st.session_state["last_verification_result"]["key_revocation"] = False if "REVOKED" in doc_reason else True
            st.stop()

        # Step 2: Signature Verification
        st.markdown("#### 2. Signature Verification")
        doc_pub_key = load_doctor_public_key(package["key_id"])
        sig_valid = verify_signature(package["prescription_data"], package["signature"], doc_pub_key)

        if sig_valid:
            st.success("Signature Verification: **✓ VALID**")
            log_audit_event("Signature Verification", package["pharmacy_id"], "VALID", "Verified")
        else:
            st.error("Signature Verification: **✗ INVALID**\n« The prescription may have been modified or the signature is not from the registered doctor. »")
            log_audit_event("Signature Verification", package["pharmacy_id"], "INVALID", "Discrepancy")
            st.session_state["last_verification_result"]["integrity"] = False
            st.session_state["last_verification_result"]["tamper_detection"] = False
            st.stop()

        # Step 3: Session Key Recovery
        st.markdown("#### 3. Session Key Recovery")
        pharm_key_valid, pharm_reason, pharm_meta = check_key_status(package["pharmacy_key_id"])
        if not pharm_key_valid:
            st.error(f"Session Key Recovery: **✗ REJECTED** (Reason: Pharmacy key is expired/revoked - {pharm_reason})")
            st.session_state["last_verification_result"]["key_revocation"] = False if "REVOKED" in pharm_reason else True
            st.session_state["last_verification_result"]["key_expiration"] = False if "EXPIRED" in pharm_reason else True
            st.stop()

        pharm_priv_key = load_pharmacy_private_key(package["pharmacy_key_id"])
        recovered_session_key = unwrap_session_key(package["wrapped_session_key"], pharm_priv_key)
        st.success("Session Key: **✓ Successfully recovered**")

        # Step 4: Prescription Decryption
        st.markdown("#### 4. Prescription Decryption")
        try:
            decrypted_rx = decrypt_prescription({
                "ciphertext_b64": package["encrypted_prescription"],
                "nonce_b64": package["nonce"],
                "tag_b64": package["tag"],
                "full_encrypted_b64": package.get("full_encrypted_b64")
            }, recovered_session_key)
            st.success("Prescription Decryption: **✓ SUCCESS**")
        except ValueError as ve:
            st.error(f"Prescription Decryption: **✗ DECRYPTION FAILED**\n« The encrypted prescription may have been modified. » ({str(ve)})")
            st.session_state["last_verification_result"]["integrity"] = False
            st.session_state["last_verification_result"]["tamper_detection"] = False
            st.stop()

        # Step 5: Final Prescription Details Output
        st.markdown("---")
        st.subheader("📋 Verified Prescription Details")
        st.code(f"""----------------------------------------
PATIENT ID : {decrypted_rx.get('patient_id')}
MEDICINE   : {decrypted_rx.get('medicine')}
DOSAGE     : {decrypted_rx.get('dosage')}
FREQUENCY  : {decrypted_rx.get('frequency')}
DURATION   : {decrypted_rx.get('duration')}
----------------------------------------""", language="text")
        st.success("Prescription Integrity: **✓ VERIFIED**\nPrescription sent securely.")

        st.session_state["last_verification_result"] = {
            "confidentiality": True, "integrity": True, "authentication": True,
            "key_exchange": True, "tamper_detection": True, "key_expiration": True, "key_revocation": True
        }


# ==========================================
# PAGE 3: KEY MANAGEMENT
# ==========================================
elif menu == "🔑 Key Management":
    st.header("🔑 Cryptographic Key Management Lifecycle")
    all_keys = list_all_keys()
    if all_keys:
        st.dataframe(pd.DataFrame(all_keys)[["key_id", "owner_id", "purpose", "status", "expires_at"]], use_container_width=True)

    st.markdown("---")
    st.subheader("Key Expiration & Revocation Controls")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("⏰ Expire Doctor Key", use_container_width=True): expire_key("DOC102-SIGN-001"); st.rerun()
    with col2:
        if st.button("🚫 Revoke Doctor Key", use_container_width=True): revoke_key("DOC102-SIGN-001"); st.rerun()
    with col3:
        if st.button("⏰ Expire Pharmacy Key", use_container_width=True): expire_key("PHARM001-ENC-001"); st.rerun()
    with col4:
        if st.button("🚫 Revoke Pharmacy Key", use_container_width=True): revoke_key("PHARM001-ENC-001"); st.rerun()

    if st.button("🟢 Restore Default Keys to ACTIVE", use_container_width=True, type="secondary"):
        activate_key("DOC102-SIGN-001"); activate_key("PHARM001-ENC-001"); st.rerun()

    st.markdown("---")
    st.subheader("Key Rotation")
    col_rot1, col_rot2 = st.columns(2)
    with col_rot1:
        if st.button("🔄 Rotate Doctor Key Pair", use_container_width=True):
            rotate_key("DOC102", "doctor", "SIGNING")
            st.success("Doctor Key Rotated!")
            st.rerun()
    with col_rot2:
        if st.button("🔄 Rotate Pharmacy Key Pair", use_container_width=True):
            rotate_key("PHARM001", "pharmacy", "ENCRYPTION")
            st.success("Pharmacy Key Rotated!")
            st.rerun()


# ==========================================
# PAGE 4: SECURITY TESTING
# ==========================================
elif menu == "🧪 Security Testing & Attack Simulation":
    st.header("🧪 Security Testing & Attack Simulation")
    package = st.session_state.get("transmission_package")
    if not package:
        st.info("ℹ️ Please generate a prescription in Doctor System first.")
    else:
        st.subheader("Active Test Package")
        st.code(f"Prescription ID : {package['prescription_id']}\nDoctor ID       : {package['doctor_id']}\nStatus          : {'⚠️ TAMPERED' if package.get('is_tampered') else '✓ CLEAN ORIGINAL'}", language="text")

        st.markdown("---")
        st.subheader("Attack Simulation Vectors")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("☣️ Simulate Tampering", use_container_width=True):
                package["prescription_data"]["medicine"] = "Morphine (TAMPERED)"
                package["encrypted_prescription"] = base64.b64encode(b"TAMPERED_CIPHERTEXT").decode('utf-8')
                package["is_tampered"] = True
                st.session_state["transmission_package"] = package
                st.warning("Prescription payload tampered!")
        with col2:
            if st.button("❌ Simulate Bad Signature", use_container_width=True):
                package["signature"] = base64.b64encode(b"CORRUPTED_SIGNATURE").decode('utf-8')
                package["is_tampered"] = True
                st.session_state["transmission_package"] = package
                st.warning("Signature corrupted!")
        with col3:
            if st.button("⏰ Expire Doctor Key", use_container_width=True): expire_key("DOC102-SIGN-001"); st.warning("Doctor Key Expired!")
        with col4:
            if st.button("🚫 Revoke Pharmacy Key", use_container_width=True): revoke_key("PHARM001-ENC-001"); st.error("Pharmacy Key Revoked!")

        st.markdown("---")
        if st.button("🔄 Reset Test & Restore Clean State", type="primary", use_container_width=True):
            activate_key("DOC102-SIGN-001"); activate_key("PHARM001-ENC-001")
            st.session_state["last_verification_result"] = {k: True for k in st.session_state["last_verification_result"]}
            st.success("Test reset!")


# ==========================================
# PAGE 5: AUDIT LOG
# ==========================================
elif menu == "📜 Audit Log":
    st.header("📜 Educational Audit Log")
    logs = load_audit_logs()
    if logs:
        st.dataframe(pd.DataFrame(logs), use_container_width=True)
    if st.button("🗑️ Clear Audit Log"):
        with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4)
        st.rerun()


# ==========================================
# PAGE 6: HOW HYBRID CRYPTOGRAPHY WORKS
# ==========================================
elif menu == "📘 How Hybrid Cryptography Works":
    st.header("📘 Architecture & Data Flow")
    
    if DIAGRAM_PATH.exists():
        st.image(str(DIAGRAM_PATH), use_container_width=True)

    st.markdown("""
    ### Why Combine AES and RSA (Hybrid Approach)?
    
    1. **Speed & Scalability (AES-256-GCM)**:
       Symmetric encryption algorithms like AES are computationally extremely fast and suited for encrypting data of any size.
       
    2. **Key Distribution & Identity (RSA-3072)**:
       Asymmetric encryption solves the key distribution problem. The secret AES session key is wrapped using RSA-OAEP.
       
    3. **Authenticity & Non-Repudiation (RSA-PSS)**:
       The sender signs the data payload using their RSA private key. Anyone with the sender's public key can verify authenticity.
    """)


# ==========================================
# PAGE 7: SECURITY CONCEPTS
# ==========================================
elif menu == "🎓 Security Concepts & Defense":
    st.header("🎓 Core Security Concepts")
    with st.expander("🔒 1. Confidentiality (AES-256-GCM)", expanded=True):
        st.markdown("AES-256-GCM encrypts prescription data so eavesdroppers cannot read it.")
    with st.expander("🛡️ 2. Integrity (AES-GCM Auth Tag & RSA-PSS Signature)"):
        st.markdown("Authentication tag and digital signatures detect any modification in transit.")
    with st.expander("👤 3. Authentication & Non-Repudiation (RSA-PSS)"):
        st.markdown("Confirms Doctor identity and prevents denial of prescription authorship.")
    with st.expander("🗝️ 4. Key Management & Lifetime Validation"):
        st.markdown("Verifies: `Exist ➔ Not Revoked ➔ Not Expired ➔ Status == ACTIVE`")
