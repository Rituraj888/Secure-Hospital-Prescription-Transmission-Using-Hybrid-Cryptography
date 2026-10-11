# Secure Hospital Prescription Transmission Using Hybrid Cryptography

A comprehensive educational prototype demonstrating secure electronic transmission of hospital prescriptions between a Doctor and Pharmacy using **Hybrid Cryptography** (AES-256-GCM + RSA-3072 OAEP & PSS).

---

## 1. Project Objective

The objective of this project is to develop a Python-based secure prescription transmission system that protects prescription confidentiality, integrity, and authenticity during transmission between a hospital Doctor and a Pharmacy.

The system demonstrates:
- **Confidentiality**: Protected via AES-256-GCM symmetric encryption.
- **Integrity**: Guaranteed by AES-GCM authentication tags and RSA-PSS digital signatures.
- **Authenticity & Non-Repudiation**: Proven via Doctor RSA digital signatures.
- **Secure Key Exchange**: AES session keys wrapped using Pharmacy's RSA-3072 public key with RSA-OAEP.
- **Key Management Lifecycle**: Automatic validation of key existence, expiration, revocation, and rotation.
- **Tamper & Attack Simulation**: Built-in security testing for college demonstration and viva defense.

> **Notice:** Educational prototype — synthetic patient data only. Do not enter real patient or health information.

---

## 2. Cryptographic Architecture & Flow

This application combines symmetric encryption (fast payload encryption) and asymmetric encryption (key wrapping and digital signing):

```
Prescription Data (Synthetic)
     |
     v
AES-256-GCM Encryption --------------> Encrypted Prescription Ciphertext
     |                                          |
     v                                          |
AES Session Key (256-bit)                      |
     |                                          |
     v                                          |
RSA-OAEP Encryption (Pharmacy Public Key)      |
     |                                          |
     v                                          |
Wrapped Session Key                             |
     |                                          |
Doctor RSA Private Key                          |
     |                                          |
     v                                          |
Digital Signature (RSA-PSS) --------------------+
                                                |
                                                v
                                       Secure Package JSON
                                                |
                                                v
                                         Pharmacy System
                                                |
                    +---------------------------+---------------------------+
                    |                                                       |
                    v                                                       v
       Verify Digital Signature (RSA-PSS)                      Decrypt Session Key (RSA-OAEP)
                    |                                                       |
                    v                                                       v
          Authenticate Doctor                                       Recover AES Key
                                                                            |
                                                                            v
                                                                 AES-256-GCM Decryption
                                                                            |
                                                                            v
                                                                   Verified Prescription
```

---

## 3. Technologies Used

- **Python 3.10+**
- **Streamlit** (Web Application Framework)
- **PyCA Cryptography** (`cryptography` library for AES-GCM, RSA-OAEP, RSA-PSS)
- **JSON** (Data serialization & transmission package format)
- **Pandas** (Table rendering for key management and audit logging)

---

## 4. Key Cryptographic Algorithms

| Security Goal | Algorithm | Key Size / Padding | Standard / Reference |
|---|---|---|---|
| **Payload Encryption** | AES-GCM | 256-bit key, 96-bit nonce, 128-bit tag | NIST SP 800-38D |
| **Session Key Protection** | RSA-OAEP | 3072-bit key, SHA-256, MGF1 SHA-256 | PKCS #1 v2.2 |
| **Digital Signature** | RSA-PSS | 3072-bit key, SHA-256, Salt length MAX | PKCS #1 v2.2 |
| **Key Status Evaluation** | Strict State Flow | `Exist ➔ Not Revoked ➔ Not Expired ➔ Active` | Key Management Lifecycle |

---

## 5. Project Directory Structure

```
secure_prescription/
├── app.py                  # Main Streamlit Web Application
├── requirements.txt        # Dependencies
├── README.md               # Complete Project Documentation & Viva Q&A
│
├── crypto/                 # Cryptographic Modules
│   ├── __init__.py
│   ├── encryption.py       # AES-256-GCM Symmetric Encryption / Decryption
│   ├── rsa_utils.py        # RSA Key Pair Generation & RSA-OAEP Key Wrapping
│   ├── signatures.py       # RSA-PSS Digital Signatures & Verification
│   └── key_manager.py      # Key Storage, Status Verification, Revocation & Rotation
│
├── data/                   # JSON Storage
│   ├── doctors.json        # Synthetic Doctor Registry
│   ├── pharmacies.json     # Synthetic Pharmacy Registry
│   └── audit_log.json      # Educational Audit Log File
│
└── keys/                   # Key Files (PEM & Metadata)
    ├── doctor/             # Doctor RSA Private/Public Key PEM & Meta
    └── pharmacy/           # Pharmacy RSA Private/Public Key PEM & Meta
```

---

## 6. Installation & Quick Start

### Step 1 — Navigate to Project Directory
```bash
cd secure_prescription
```

### Step 2 — Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Run the Streamlit Application
```bash
streamlit run app.py
```

Open your browser at: `http://localhost:8501`

---

## 7. Demonstration Guide

### A. Doctor System (Prescription Creation & Transmission)
1. Select **👨‍⚕️ Doctor System** from sidebar.
2. Observe input fields pre-filled with synthetic data (Doctor: `DOC102`, Patient: `PAT501`, Medicine: `Amoxicillin`, Dosage: `500 mg`).
3. Click **🚀 Send Prescription Securely**.
4. Observe step-by-step workflow:
   - Step 1: Prescription Created
   - Step 2: Session Key Generated (AES-256-GCM)
   - Step 3: Prescription Encrypted
   - Step 4: Digital Signature Generated (RSA-PSS)
   - Step 5: Session Key Protected (RSA-OAEP)

### B. Pharmacy System (Verification & Decryption)
1. Select **🏥 Pharmacy System** from sidebar.
2. View received secure package details.
3. Observe automatic verification sequence:
   - Doctor Authentication (Key status check)
   - Signature Verification (RSA-PSS Public Key check)
   - Session Key Recovery (Pharmacy RSA Private Key unwrap)
   - Prescription Decryption (AES-256-GCM tag verification)
4. View final verified prescription output.

### C. Security Testing & Attack Simulation
1. Select **🧪 Security Testing & Attack Simulation**.
2. Test **Prescription Tampering**: Click `☣️ Simulate Prescription Tampering`. Go to Pharmacy System page to see Signature / Tag verification failure.
3. Test **Invalid Signature**: Click `❌ Simulate Invalid Signature`. Observe signature verification failure.
4. Test **Expired Doctor Key**: Click `⏰ Simulate Expired Doctor Key`. Observe Doctor Authentication rejection.
5. Test **Revoked Pharmacy Key**: Click `🚫 Simulate Revoked Pharmacy Key`. Observe Session Key Recovery rejection.
6. Click `🔄 Reset Test` to restore clean state.

---

## 8. Key Management & Rotation

### Key Verification Sequence
Before accepting any cryptographic operation, key manager enforces:
$$\text{Check Exist} \rightarrow \text{Check Revoked} \rightarrow \text{Check Expired} \rightarrow \text{Check Active} \rightarrow \text{Accept Key}$$

### Key Rotation
Select **🔑 Key Management** sidebar page and click **🔄 Rotate Doctor Key Pair**. The previous key is set to `EXPIRED` and a fresh RSA 3072-bit key pair is created and registered as `ACTIVE`.

---

## 9. Security Considerations & Limitations

- **Educational Scope**: Designed specifically for academic demonstration and viva defense.
- **Private Key Protection**: Private keys are stored locally in PEM files and are never printed, displayed in the Streamlit UI, or written to audit logs.
- **No Internet Required**: Works 100% offline once Python dependencies are installed.

---

## 10. Future Enhancements

1. Integration with Hardware Security Modules (HSM) or cloud KMS (e.g. AWS KMS).
2. X.509 PKI Certificates for Doctor & Pharmacy identity attestation.
3. Multi-hospital tenant isolation with RBAC (Role-Based Access Control).
