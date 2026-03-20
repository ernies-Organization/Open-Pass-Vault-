# Open Pass Vault

## ⚠️ Important Notice

Open Pass Vault is an **educational, open‑source project**. It is **NOT** an official or professionally audited password manager.

### Please read this carefully:
- This software is licensed under the **MIT License**.
- It is provided **AS IS**, with **NO WARRANTY**, **NO GUARANTEE**, and **NO RESPONSIBILITY** for password loss, theft, corruption, or any other damage.
- By using this software, **you accept full responsibility** for your data.
- If you need *professional‑grade* password security, use an official password manager (Bitwarden, Proton Pass, 1Password, NordPass, etc.).
- You are allowed to **modify, inspect, rebuild, and customize** the code under the MIT License, but you do so at your own risk.

---

# Open Pass Vault — README  
A fully offline, open‑source password manager with advanced multi‑factor authentication.

🔗 **Main Script:**  
**`open_pass_vault.py`**

🔗 **License:**  
**MIT License**

---

## 📌 Overview
Open Pass Vault is a privacy‑focused, offline password manager.  
Everything is stored **locally**, with **zero cloud usage** and **no telemetry**.

All vault data is encrypted using:
- **PBKDF2‑HMAC‑SHA256 (310,000 iterations)**  
- **Fernet symmetric encryption**

Open Pass Vault is perfect for:
- Learning about encryption & authentication
- Running on offline machines / air‑gapped systems
- Users who want completely local control
- Anyone who wants to inspect or modify the code

---

## 🔐 Features
- Fully offline — NO cloud, NO accounts, NO tracking
- Encrypted vault (`python_password_manager_vault.bin`)
- Auth file with encrypted 2FA secrets (`python_password_manager_auth.json`)
- Multiple offline 2FA methods:
  - **TOTP** (Authenticator apps)
  - **HOTP** (event‑based)
  - **Backup Codes** (one‑time use)
  - **Grid Card Authentication** (coordinate system)
- Password strength checks
- Password generator
- Clipboard copying (if `pyperclip` is installed)
- Auto‑lock session timeout (10 minutes)
- Exportable:
  - Backup codes
  - Grid card
- Fully modifiable open‑source Python code

---

## ⚠️ Extended Security Disclaimer
This software is **NOT professionally audited**.

If you require reliable, enterprise‑grade, or mission‑critical password security, use a real password manager:

- Bitwarden  
- Proton Pass  
- 1Password  
- Keeper  
- NordPass  
- Dashlane  

Open Pass Vault is designed for **education and local experimentation**, **NOT** high‑risk or professional use.

---

## 🚀 Getting Started

Clone the repository:

```bash
git clone https://github.com/ernies-Organization/Open-Pass-Vault-.git
cd Open-Pass-Vault-