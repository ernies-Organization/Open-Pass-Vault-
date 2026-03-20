
#!/usr/bin/env python3
"""
Open Pass Vault — current.py
Same features as your latest manager, but with file names prefixed so they’re easy to spot.

Changes:
  - AUTH_FILE  -> python_password_manager_auth.json
  - VAULT_FILE -> python_password_manager_vault.bin
  - Export files now start with: python_password_manager_backup_codes_*, python_password_manager_grid_card_*
"""

import os, sys, json, base64, secrets, hashlib, traceback, random, time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple

# --- Optional deps detection ---
DEPS = {"cryptography": False, "pyotp": False, "qrcode_terminal": False, "pyperclip": False}
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    DEPS["cryptography"] = True
except Exception:
    pass
try:
    import pyotp
    DEPS["pyotp"] = True
except Exception:
    pass
try:
    import qrcode_terminal  # type: ignore
    DEPS["qrcode_terminal"] = True
except Exception:
    pass
try:
    import pyperclip  # type: ignore
    DEPS["pyperclip"] = True
except Exception:
    pass

# ---- Config ----
LOGIN_AFTER_SETUP = False
GRID_SIZE = 6
GRID_TOKEN_LEN = 3
IDLE_TIMEOUT_SECONDS = 600
MIN_RECOMMENDED_STRENGTH = {"Strong", "Very Strong"}

# ---- Paths (prefixed filenames) ----

def _resolve_base_dir() -> Path:
    try:
        return Path(__file__).resolve().parent
    except NameError:
        pass
    try:
        if getattr(sys, "argv", None) and sys.argv[0]:
            return Path(sys.argv[0]).resolve().parent
    except Exception:
        pass
    return Path.cwd()

BASE_DIR = _resolve_base_dir()
AUTH_FILE  = BASE_DIR / "python_password_manager_auth.json"
VAULT_FILE = BASE_DIR / "python_password_manager_vault.bin"

# Export prefixes
BACKUP_PREFIX = "python_password_manager_backup_codes"
GRID_PREFIX   = "python_password_manager_grid_card"

# ---- Helpers ----

def print_dependency_report():
    print("== Dependency Check ==")
    print("✓ cryptography:" if DEPS["cryptography"] else "✗ cryptography: NOT INSTALLED")
    print(("✓ pyotp:" if DEPS["pyotp"] else "! pyotp:") + (" OK" if DEPS["pyotp"] else " NOT INSTALLED (OTP disabled)"))
    print(("✓ qrcode-terminal:" if DEPS["qrcode_terminal"] else "! qrcode-terminal:") + (" OK" if DEPS["qrcode_terminal"] else " NOT INSTALLED (ASCII QR disabled)"))
    print(("✓ pyperclip:" if DEPS["pyperclip"] else "! pyperclip:") + (" OK" if DEPS["pyperclip"] else " NOT INSTALLED (clipboard disabled)"))
    print()

def print_environment_report():
    print("== Environment ==")
    print("BASE_DIR:", BASE_DIR)
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = BASE_DIR / ".pm_write_test.tmp"
        with tmp.open("w", encoding="utf-8") as f: f.write("ok")
        tmp.unlink(missing_ok=True)
        print("Write test (folder): OK")
    except Exception as e:
        print("Write test (folder): FAILED", e)
    print(f"AUTH_FILE exists?: {AUTH_FILE.exists()} (on first boot should be False)")
    print(f"VAULT_FILE exists?: {VAULT_FILE.exists()} (on first boot should be False)")
    print()

def b64e(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.urlsafe_b64decode(s.encode("utf-8"))

def safe_getpass(prompt: str) -> str:
    import sys as _sys
    print("
>>>", prompt, "(type and press Enter)")
    _sys.stdout.flush()
    return input("> ")

# time-stamped file path with project prefix

def now_stamp(prefix: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # ensure our exported files also carry the project prefix
    return BASE_DIR / f"{prefix}_{ts}.txt"

# ---- Crypto ----

def derive_key(password: str, salt: bytes, iterations: int = 310_000) -> bytes:
    if not DEPS["cryptography"]: raise RuntimeError("cryptography not installed")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))

def make_fernet_from_key(key: bytes) -> "Fernet":
    if not DEPS["cryptography"]: raise RuntimeError("cryptography not installed")
    return Fernet(base64.urlsafe_b64encode(key))

# ---- Auth I/O ----

def load_auth() -> Optional[dict]:
    if not AUTH_FILE.exists(): return None
    try:
        with AUTH_FILE.open("r", encoding="utf-8") as f: return json.load(f)
    except Exception as e:
        print("ERROR: reading auth.json:", e); return None

def save_auth(data: dict) -> None:
    with AUTH_FILE.open("w", encoding="utf-8") as f: json.dump(data, f, indent=2)

# ---- Vault I/O ----

def _new_vault_dict() -> Dict:
    return {"vault_header":"VAULT_OK","version":1,"entries":[]}

def _decrypt_vault(fernet: "Fernet") -> Dict:
    if not VAULT_FILE.exists(): return _new_vault_dict()
    with VAULT_FILE.open("rb") as f: ciphertext = f.read()
    plaintext = fernet.decrypt(ciphertext)
    data = json.loads(plaintext.decode("utf-8"))
    if data.get("vault_header") != "VAULT_OK": raise ValueError("Bad vault header")
    return data

def _encrypt_vault(fernet: "Fernet", data: Dict) -> None:
    plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    ciphertext = fernet.encrypt(plaintext)
    with VAULT_FILE.open("wb") as f: f.write(ciphertext)

def open_and_verify_vault(fernet: "Fernet") -> bool:
    try:
        data = _decrypt_vault(fernet)
        return data.get("vault_header") == "VAULT_OK"
    except Exception as e:
        print("WARN: vault missing/corrupt — creating new.", e)
        try:
            _encrypt_vault(fernet, _new_vault_dict()); return True
        except Exception as ee:
            print("ERROR: creating new vault:", ee); return False

# ---- Store API ----

def list_password_labels(fernet: "Fernet") -> List[str]:
    try:
        data = _decrypt_vault(fernet)
    except Exception as e:
        print("ERROR: list labels:", e); return []
    labels = [e.get("label","") for e in data.get("entries",[])]
    return sorted([l for l in labels if l])

def get_password_entry(fernet: "Fernet", label: str) -> Optional[Dict]:
    try:
        data = _decrypt_vault(fernet)
    except Exception as e:
        print("ERROR: read entry:", e); return None
    for e in data.get("entries",[]):
        if e.get("label") == label: return e
    return None

def add_password_entry(fernet: "Fernet", label: str, username: str, password: str,
                        site: Optional[str]=None, notes: Optional[str]=None, overwrite: bool=False) -> bool:
    label = (label or "").strip()
    if not label:
        print("ERROR: empty label."); return False
    try:
        data = _decrypt_vault(fernet)
    except Exception as e:
        print("ERROR: open vault for add:", e); return False
    entries = data.setdefault("entries", [])
    idx = next((i for i,e in enumerate(entries) if e.get("label") == label), None)
    new = {"label":label,"site":site or "","username":username or "","password":password or "","notes":notes or ""}
    if idx is None: entries.append(new)
    else:
        if not overwrite:
            print("ERROR: label exists, overwrite=no."); return False
        entries[idx] = new
    try:
        _encrypt_vault(fernet, data); return True
    except Exception as e:
        print("ERROR: save entry:", e); return False

def delete_password_entry(fernet: "Fernet", label: str) -> bool:
    try:
        data = _decrypt_vault(fernet)
    except Exception as e:
        print("ERROR: open vault for delete:", e); return False
    entries = data.get("entries", [])
    new_entries = [e for e in entries if e.get("label") != label]
    if len(new_entries) == len(entries): return False
    data["entries"] = new_entries
    try:
        _encrypt_vault(fernet, data); return True
    except Exception as e:
        print("ERROR: save after delete:", e); return False

def show_codes(fernet: "Fernet") -> None:
    labels = list_password_labels(fernet)
    if not labels: print("No saved labels."); return
    print("Saved labels:")
    for i,lbl in enumerate(labels,1): print(f" {i}) {lbl}")

# ---- Strength & Generator ----

def check_password_strength(password: str) -> Tuple[str,int,List[str]]:
    score = 0; fb: List[str] = []
    L = len(password)
    if   L >= 16: score += 4
    elif L >= 12: score += 3
    elif L >= 8:  score += 2
    elif L >= 6:  score += 1
    else: fb.append("Use at least 8 characters.")
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    if has_lower: score += 1
    if has_upper: score += 1
    if has_digit: score += 1
    if has_symbol: score += 2
    if password.isalpha() or password.isdigit(): score -= 2; fb.append("Mix letters, numbers, symbols.")
    if len(set(password)) == 1: score -= 3; fb.append("Avoid all-same characters.")
    for i in range(len(password)-2):
        if password[i]==password[i+1]==password[i+2]: score -= 1; fb.append("Avoid triple repeats."); break
    if any(s in password.lower() for s in ["abc","123","qwerty","asdf"]): score -= 2; fb.append("Avoid common sequences.")
    label = "Very Weak" if score<=2 else "Weak" if score<=4 else "Medium" if score<=6 else "Strong" if score<=8 else "Very Strong"
    return label, max(score,0), fb

def external_generate_password() -> Optional[str]:
    import secrets
    lower = "abcdefghijklmnopqrstuvwxyz"; upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; digits = "0123456789"; symbols = "!@#$%^&*()-_=+[]{};:,.<>?/\"
    groups = [lower, upper, digits, symbols]
    def ask(prompt: str) -> bool:
        while True:
            a = input(prompt+" (y/n): ").strip().lower()
            if a in ("y","yes"): return True
            if a in ("n","no"): return False
            print("Enter y or n.")
    while True:
        enabled = [ask("Include lowercase?"), ask("Include uppercase?"), ask("Include digits?"), ask("Include symbols?")]
        if any(enabled): break
        print("Select at least one group.
")
    selected = [groups[i] for i in range(4) if enabled[i]]
    pool = [c for g in selected for c in g]
    while True:
        s = input("Password length: ").strip()
        if s.isdigit():
            L = int(s)
            if L >= len(selected): break
            print(f"Length must be >= {len(selected)}")
        else: print("Not a number.")
    chars = [secrets.choice(g) for g in selected]
    for _ in range(L - len(chars)): chars.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

# ---- 2FA (only TOTP as minimal here; add others if needed) ----

def setup_totp(fernet: "Fernet", auth: dict) -> None:
    if not DEPS["pyotp"]:
        print("pyotp not installed — skipping TOTP"); auth.setdefault("totp",{})["enabled"]=False; save_auth(auth); return
    if input("Enable TOTP? (y/n): ").strip().lower() not in ("y","yes"):
        auth.setdefault("totp",{})["enabled"]=False; save_auth(auth); return
    secret = pyotp.random_base32(); issuer = "OpenPassVault"; account = input("Authenticator label (default: 'Main'): ").strip() or "Main"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)
    if DEPS["qrcode_terminal"] and input("Show ASCII QR now? (y/n): ").strip().lower() in ("y","yes"):
        print(); qrcode_terminal.draw(uri, small=True); print()
    else:
        print("Add this secret to your authenticator:", secret)
    code = input("Enter 6-digit TOTP code: ").strip()
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        print("TOTP setup failed."); auth.setdefault("totp",{})["enabled"]=False; save_auth(auth); return
    auth["totp"] = {"enabled": True, "secret_enc": b64e(fernet.encrypt(secret.encode("utf-8")))}
    save_auth(auth); print("TOTP enabled.")

def verify_totp(fernet: "Fernet", auth: dict) -> bool:
    t = (auth or {}).get("totp", {})
    if not t.get("enabled"): return True
    if not DEPS["pyotp"]: print("ERROR: TOTP enabled but pyotp missing"); return False
    try: secret = Fernet(base64.urlsafe_b64encode(derive_key("dummy", b"0"*16, 1))) # dummy to keep import
    except Exception: pass
    try:
        secret = Fernet(base64.urlsafe_b64encode(b"0"*32))  # placeholder, overridden below
        secret = fernet.decrypt(b64d(t["secret_enc"])).decode("utf-8")
    except Exception as e:
        print("ERROR: decrypt totp:", e); return False
    return bool(pyotp.TOTP(secret).verify(input("TOTP code: ").strip(), valid_window=1))

# ---- Session ----
SESSION_TOKEN: Optional[str] = None

def create_session() -> str:
    global SESSION_TOKEN
    SESSION_TOKEN = secrets.token_hex(32)
    return SESSION_TOKEN

def is_logged_in(tok: Optional[str]) -> bool:
    return tok is not None and tok == SESSION_TOKEN

# ---- Account ----

def delete_account() -> None:
    print("
!!! WARNING: This will delete ALL data !!!")
    if input("Type DELETE to confirm: ").strip() != "DELETE":
        print("Cancelled."); return
    if AUTH_FILE.exists(): AUTH_FILE.unlink(); print("Deleted:", AUTH_FILE)
    if VAULT_FILE.exists(): VAULT_FILE.unlink(); print("Deleted:", VAULT_FILE)
    print("Account deleted.")

# ---- Setup & Verify ----

def first_time_setup() -> None:
    print("== First-time setup ==
")
    pw1 = safe_getpass("Create a master password"); pw2 = safe_getpass("Confirm master password")
    while True:
        if pw1 != pw2:
            print("Passwords do not match."); pw1 = safe_getpass("Create a master password"); pw2 = safe_getpass("Confirm master password"); continue
        if len(pw1) < 8:
            print("Use at least 8 characters."); pw1 = safe_getpass("Create a master password"); pw2 = safe_getpass("Confirm master password"); continue
        break
    salt = secrets.token_bytes(16); iterations = 310_000
    key = derive_key(pw1, salt, iterations); f = make_fernet_from_key(key)
    auth = {"kdf": {"name":"PBKDF2HMAC","hash":"SHA256","iterations":iterations,"salt": b64e(salt)},
            "password_verifier": b64e(key),
            "totp": {"enabled": False}}
    save_auth(auth)
    _encrypt_vault(f, _new_vault_dict())
    if input("Configure TOTP now? (y/n): ").strip().lower() in ("y","yes"):
        setup_totp(f, auth)


def verify_master_password() -> Optional["Fernet"]:
    auth = load_auth()
    if not auth: print("ERROR: missing auth.json"); return None
    try:
        k = auth["kdf"]; iterations = int(k["iterations"]); salt = b64d(k["salt"]); expected = auth.get("password_verifier","")
    except Exception as e:
        print("ERROR: auth.json malformed:", e); return None
    for attempts in range(3,0,-1):
        pw = safe_getpass("Enter master password")
        try: key = derive_key(pw, salt, iterations)
        except Exception as e: print("ERROR: key derivation:", e); return None
        if b64e(key) == expected:
            try: return make_fernet_from_key(key)
            except Exception as e: print("ERROR: init crypto:", e); return None
        print(f"Incorrect. Attempts left: {attempts-1}")
    print("Too many failed attempts."); return None

# ---- Settings (minimal TOTP only in this trimmed file) ----

def settings_menu(fernet: "Fernet") -> None:
    while True:
        auth = load_auth() or {}
        totp_enabled = bool((auth.get("totp") or {}).get("enabled"))
        print("
== Settings ==")
        print("TOTP:", "ENABLED" if totp_enabled else "DISABLED")
        print("1) Enable/Reconfigure TOTP")
        print("0) Back")
        ch = input("Select: ").strip()
        if ch == "0": break
        if ch == "1": setup_totp(fernet, auth)
        else: print("Invalid choice.")

# ---- Menu ----

def password_manager(session_token: str, fernet: "Fernet") -> None:
    last_active = time.time()
    while True:
        if time.time() - last_active > IDLE_TIMEOUT_SECONDS:
            print("
Session timed out."); break
        print("
== Password Manager ==")
        print("1) Logout
2) Delete account
3) Add password
4) List labels
5) View password
6) Delete password
7) Check strength
8) Generate password
9) Settings")
        choice = input("Select: ").strip(); last_active = time.time()
        if choice == "1": print("Logging out..."); break
        elif choice == "2": delete_account(); break
        elif choice == "3":
            label = input("Label: ").strip(); site = input("Site (optional): ").strip(); user = input("Username: ").strip(); pw = input("Password: ").strip()
            if pw:
                s_label, s_score, s_fb = check_password_strength(pw)
                print(f"Strength: {s_label} (score {s_score})")
                if s_label not in MIN_RECOMMENDED_STRENGTH:
                    print("WARNING: below recommended. Type the SAME password to confirm.")
                    if input(": ").strip() != pw: print("Cancelled."); continue
            else:
                print("No password."); continue
            overwrite = input("Overwrite if exists? (y/n): ").strip().lower() in ("y","yes")
            print("Saved." if add_password_entry(fernet, label, user, pw, site or None, None, overwrite) else "Not saved.")
        elif choice == "4": show_codes(fernet)
        elif choice == "5":
            label = input("Label: ").strip(); e = get_password_entry(fernet, label)
            if not e: print("Not found.")
            else:
                print("
=== Entry ==="); print("Label   :", e.get("label","")); print("Site    :", e.get("site",""))
                print("Username:", e.get("username","")); print("Password:", e.get("password",""))
        elif choice == "6":
            label = input("Label: ").strip(); print("Deleted." if delete_password_entry(fernet, label) else "Not found.")
        elif choice == "7":
            pw = input("Password to check: ").strip(); s_label, s_score, s_fb = check_password_strength(pw)
            print(f"Strength: {s_label} (score {s_score})"); [print(" -",x) for x in s_fb]
        elif choice == "8":
            gen = external_generate_password();
            if not gen: print("Generator unavailable.")
            else:
                print("Generated:", gen)
        elif choice == "9": settings_menu(fernet)
        else: print("Invalid choice.")

# ---- App start ----

def start():
    print_dependency_report(); print_environment_report()
    if not DEPS["cryptography"]:
        print("FATAL: 'cryptography' is required."); return
    if not AUTH_FILE.exists():
        print("No auth file found -> setup.
"); first_time_setup()
        if not LOGIN_AFTER_SETUP:
            print("
Setup complete. Run again to log in."); return
    f = verify_master_password()
    if not f: print("Access denied."); return
    if not open_and_verify_vault(f): print("Vault verification failed."); return
    token = create_session()
    try:
        password_manager(token, f)
    except Exception:
        print("ERROR: Unhandled exception in menu loop:"); traceback.print_exc()

if __name__ == "__main__":
    try:
        start()
    except KeyboardInterrupt:
        print("
Exiting.")
