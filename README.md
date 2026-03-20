# Open Pass Vault

## ⚠️ Important Notice

Open Pass Vault is an **educational, open‑source project**. It is **NOT** an official or professionally audited password manager.

### You must read the following disclaimer:
- This software is licensed under the **[MIT License](https://github.com/ernies-Organization/Open-Pass-Vault-/blob/main/LICENSE)**.
- It is provided **AS IS**, with **NO WARRANTY**, **NO GUARANTEE**, and **NO RESPONSIBILITY** for password loss, corruption, security issues, breaches, or any other damage.
- By using this software, **you accept full responsibility** for your data.
- If you require *professional-grade* password security, you should use a trusted, established password manager such as Bitwarden, 1Password, Proton Pass, NordPass, etc.
- You are free to **modify, inspect, rebuild, and customize** the code as allowed under the MIT License.

---

# Open Pass Vault — README
A fully offline, open‑source password manager with advanced multi‑factor authentication.

GitHub Repository: https://github.com/ernies-Organization/Open-Pass-Vault-

License: **[MIT License](https://github.com/ernies-Organization/Open-Pass-Vault-/blob/main/LICENSE)**

---

## 📌 Overview
Open Pass Vault is a privacy‑focused, offline password manager. Your vault and authentication data are stored entirely on your device.

All encryption keys are derived using **PBKDF2‑HMAC‑SHA256** with 310,000 iterations and secured using **Fernet symmetric encryption**.

This project is ideal for:
- Personal learning
- Offline‑only security setups
- Users who want a transparent and modifiable password manager

---

## 🔐 Features
- Fully offline
- Encrypted password vault (Fernet)
- Multiple offline 2FA methods:
  - TOTP
  - HOTP
  - Backup Codes
  - Grid Card authentication
- Password strength checker
- Password generator
- Clipboard copy support
- Auto‑lock timeout
- Exportable grid card and backup codes
- Easily modifiable open‑source code

---

## ⚠️ Security Disclaimer (Extended)
This software is **NOT professionally audited**.

You should NOT rely on this for mission‑critical password storage.
If you need real security, use an official, vetted password manager.

Examples include (non‑exhaustive):
- Bitwarden
- 1Password
- Keeper
- Proton Pass
- Dashlane
- NordPass

Open Pass Vault is a **learning tool**, not a certified security product.

---

## 🚀 Getting Started
Clone the repository:
```bash
git clone https://github.com/ernies-Organization/Open-Pass-Vault-.git
cd Open-Pass-Vault-
```
Run:
```bash
python password_manager.py
```

---

## 📦 Dependencies
Install:
```bash
pip install cryptography pyotp qrcode-terminal pyperclip
```

---

## 📝 License
This software is licensed under the **[MIT License](https://github.com/ernies-Organization/Open-Pass-Vault-/blob/main/LICENSE)**, meaning you may:
- Use it
- Modify it
- Distribute it
- Sell it
…as long as you keep the copyright notice.

**The authors provide zero warranty and bear zero responsibility.**

---

## ⭐ Final Note
Open Pass Vault is made to be **open, modifiable, and educational**.
If you want enterprise‑grade or fully protected password storage, use an official password manager.

Stay safe, encrypt everything, and keep learning. 🔐
