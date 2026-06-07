<div align="center">

<h1>🔐 CryptoGraphy</h1>

<p><strong>A free, open-source advanced file encryption suite with a clean GUI — protect your personal files with military-grade encryption, filename obfuscation, and one-click batch processing.</strong></p>

<p>
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-yellow?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/GUI-PyQt6-purple?style=flat-square" alt="PyQt6">
  <img src="https://img.shields.io/badge/encryption-AES--256-red?style=flat-square" alt="AES-256">
  <img src="https://img.shields.io/badge/offline-100%25-brightgreen?style=flat-square" alt="Offline">
</p>

<p>
  <a href="#-quick-start-windows-exe">⚡ Quick Start (EXE)</a> ·
  <a href="#-encryption-algorithms">Algorithms</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-run-from-source">Run from Source</a> ·
  <a href="#-how-to-use">How to Use</a> ·
  <a href="#-filename-obfuscation">Filename Obfuscation</a> ·
  <a href="#-troubleshooting">Troubleshooting</a>
</p>

</div>

---

## 📖 Table of Contents

- [What Is This?](#-what-is-this)
- [Encryption Algorithms](#-encryption-algorithms)
- [Features](#-features)
- [Quick Start — Windows EXE](#-quick-start-windows-exe)
- [Run from Source](#-run-from-source)
- [How to Use](#-how-to-use)
  - [Encrypting Files](#encrypting-files)
  - [Decrypting Files](#decrypting-files)
  - [Processing Entire Folders](#processing-entire-folders)
- [Password & Key Management](#-password--key-management)
- [Filename Obfuscation](#-filename-obfuscation)
- [The Manifest System](#-the-manifest-system)
- [File Logging](#-file-logging)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Security Notes](#-security-notes)
- [Contact & Support](#-contact--support)
- [License](#-license)

---

## 🔍 What Is This?

**CryptoGraphy** is a desktop application for encrypting and decrypting your personal files using strong, modern cryptographic algorithms. It is designed for anyone who wants an extra layer of security beyond just an OS login password — because even if someone gets into your computer, your encrypted files remain completely unreadable without your password.

**Who is this for?**
- Anyone who wants to protect sensitive personal files (documents, photos, archives)
- People who store files on shared or cloud drives and want them unreadable to others
- Users who want to encrypt files before putting them on a USB drive or sending them
- Developers and security-conscious users who want full control over their file security

Everything runs **100% locally and offline** — your files and password never leave your computer.

---

## 🔒 Encryption Algorithms

CryptoGraphy supports two industry-standard authenticated encryption algorithms:

### Fernet — AES-128-CBC + HMAC-SHA256 ⭐ Recommended
- The default algorithm. Fernet is a battle-tested symmetric encryption standard from the Python `cryptography` library.
- Uses AES-128 in CBC mode for encryption and HMAC-SHA256 for authentication (tamper detection).
- Produces a token that contains the IV, ciphertext, and MAC — self-contained and portable.
- **Best choice for most users.**

### AES-256-GCM — Authenticated Encryption
- 256-bit AES in Galois/Counter Mode (GCM). A modern authenticated encryption standard used in TLS 1.3, SSH, and military-grade applications.
- Slightly faster on modern CPUs that support AES hardware acceleration.
- Output format: `[4-byte magic][12-byte nonce][ciphertext + 16-byte GCM authentication tag]`
- **Best choice for maximum key size or hardware-accelerated environments.**

### Key Derivation
Both algorithms derive the encryption key from your password using **PBKDF2-HMAC-SHA256** with **100,000 iterations** — a standard algorithm specifically designed to slow down brute-force attacks. A 16-byte salt is applied during key derivation.

### Auto-Detection on Decryption
You **do not need to remember** which algorithm was used to encrypt a file. CryptoGraphy automatically reads the first bytes of the encrypted file and detects the algorithm before decrypting — no manual selection required.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 **Two Strong Algorithms** | Fernet (AES-128-CBC + HMAC-SHA256) and AES-256-GCM, both with authenticated encryption |
| 🔑 **PBKDF2 Key Derivation** | Passwords are hashed through 100,000 PBKDF2 iterations — resistant to brute-force |
| 📊 **Password Strength Meter** | Real-time visual feedback showing password strength as you type |
| 📂 **Batch Processing** | Encrypt or decrypt entire folders at once — all files in one operation |
| 🗂️ **Filename Obfuscation** | 5 name modes and 7 extension modes to hide what your files are |
| 📋 **Manifest System** | Saves original filenames so they can be automatically restored on decryption |
| 📈 **Dual Progress Bars** | Separate per-file progress and overall batch progress — always know what is happening |
| ⏱️ **Activity Indicator** | Live status: "Encrypting…", "Decrypting…", "Loading…" |
| 🧵 **Non-Blocking UI** | All operations run in a background thread — the UI never freezes |
| 🛡️ **Self-Exclusion** | The app never encrypts its own `.exe`, `.py`, log file, or manifest |
| 🎨 **Light / Dark Theme** | One-click toggle between light and dark themes |
| 🔑 **Key Generator** | Generate cryptographically random keys and copy them to clipboard |
| 📝 **File Logging** | Optional timestamped log written to `cryptography.log` for audit trail |
| 📊 **Operation Summary** | Detailed summary dialog after each batch operation |
| 🖱️ **Drag & Drop** | Drag files or folders directly onto the window to add them |
| 🏷️ **Algorithm Tooltips** | Hover over algorithm names for recommendation tips |
| 🪟 **Windows Hidden File Support** | Correctly handles Windows hidden file attributes |
| 📦 **Single File** | Entire app in one Python file — easy to audit and share |

---

## ⚡ Quick Start (Windows EXE)

No Python needed.

1. Go to the [**Releases**](../../releases) page of this repository.
2. Download `CryptoGraphy.exe`.
3. Double-click it — the app opens immediately. No installation required.
4. Add files or folders, enter your password, and click **⚡ START OPERATION**.

> The app is fully portable — copy it to any folder or USB drive and run it from there.

---

## 🐍 Run from Source

### Requirements

- Python 3.8 or newer — [https://www.python.org/downloads/](https://www.python.org/downloads/)
  - Windows: tick ✅ **"Add Python to PATH"** during installation
- Dependencies: `PyQt6` and `cryptography` (and optionally `pywin32` on Windows)

### Step 1 — Get the Script

Download `CryptoGraphy_V1.py` from this repository, or clone:

```bash
git clone https://github.com/Sparky2273/CryptoGraphy.git
cd CryptoGraphy
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Run

```bash
python CryptoGraphy_V1.py
```

---

## 📖 How to Use

### Encrypting Files

1. **Add targets** — click **Add Files** to select individual files, or **Add Folder** to add all files in a folder. You can also **drag and drop** files/folders onto the window.
2. **Select Encrypt** — make sure the **Encrypt** radio button is selected (it is by default).
3. **Enter a password** — type your password in the password field. The strength meter shows how strong it is.
   - Use a strong password with uppercase, lowercase, numbers, and symbols.
   - You can also use the **🔑 Key Generator** to create a random cryptographic key.
4. **Choose an algorithm** — Fernet is recommended. AES-256-GCM is available for advanced users.
5. **Configure filename obfuscation** (optional) — see the [Filename Obfuscation](#-filename-obfuscation) section.
6. **Enable manifest** (recommended when using filename obfuscation) — the manifest saves original filenames so they can be restored automatically when you decrypt.
7. **Click ⚡ START OPERATION** — confirm the operation in the dialog that appears.
8. Watch the progress bars. A **Summary Dialog** shows the result when done.

> ⚠️ **Important:** Remember your password. There is no password recovery. If you forget your password, your encrypted files cannot be decrypted.

---

### Decrypting Files

1. Add the encrypted files or folder (same as above).
2. Select the **Decrypt** radio button.
3. Enter the **same password** you used to encrypt.
4. Click **⚡ START OPERATION**.
5. The algorithm is **automatically detected** — you do not need to select it manually.
6. If a manifest is present in the folder, original filenames are **automatically restored**.

---

### Processing Entire Folders

- Click **Add Folder** and select a folder. CryptoGraphy will process every file inside it.
- The app **automatically excludes** its own executable, script, log file, and manifest — you cannot accidentally encrypt the app itself.
- The manifest (`.cg_manifest.json`) is created in the same folder as your files.

---

## 🔑 Password & Key Management

### Password Strength Meter
The meter scores your password on:
- Length (8, 12, and 16+ characters each add points)
- Uppercase letters (+12 points)
- Lowercase letters (+12 points)
- Numbers (+13 points)
- Special/punctuation characters (+13 points)

Aim for a score of 80+ (shown in green).

### Key Generator Dialog
Click the **🔑 Key Generator** button to open a dialog that generates cryptographically secure random keys. You can copy the key to clipboard and use it as your password.

> **Tip:** Store your key/password in a password manager (KeePass, Bitwarden, etc.) — never just rely on memory for files you want to keep long-term.

---

## 🗂️ Filename Obfuscation

CryptoGraphy can hide what your files are by transforming their names and extensions during encryption. This is configured in the **Obfuscation Panel**.

### Name Modes (5 options)

| Mode | What it does |
|---|---|
| **Keep original name** | Filename stays exactly the same. Default. |
| **Random name (keep extension)** | Replaces the filename with 16 random characters, keeps `.jpg`, `.pdf`, etc. |
| **Random name (no extension)** | Replaces the filename with 16 random characters and removes the extension entirely. |
| **Encrypt filename** | Derives a deterministic hash of the original name using BLAKE2b. Decrypting with the correct password produces the same hash, allowing consistent identification. |
| **Custom prefix + random** | Starts with a prefix you define (e.g., `backup_`), followed by 8 random characters. |

### Extension Modes (7 options)

| Mode | What it does |
|---|---|
| **Keep original extension** | Extension stays as-is. Default. |
| **Spoof as text format** | Randomly picks `.txt`, `.md`, `.log`, `.csv`, etc. |
| **Spoof as code format** | Randomly picks `.py`, `.js`, `.java`, `.cpp`, etc. |
| **Spoof as data format** | Randomly picks `.json`, `.xml`, `.yaml`, `.ini`, etc. |
| **Spoof as media format** | Randomly picks `.jpg`, `.png`, `.mp3`, `.mp4`, etc. |
| **Custom extension** | You type any extension you want. |
| **No extension** | Removes the extension entirely. |

---

## 📋 The Manifest System

When filename obfuscation is enabled, the original filenames are lost unless you save them somewhere. The **manifest** solves this.

- When **enabled** (checkbox ticked), CryptoGraphy creates a hidden file called `.cg_manifest.json` in the same folder as your files.
- This file maps each obfuscated filename back to its original name.
- When you **decrypt**, the manifest is read automatically and all filenames are restored to their originals.
- The manifest file is a plain JSON file — you can open it with any text editor to inspect it.

> **Important:** If you use filename obfuscation and later **lose the manifest**, original filenames cannot be recovered automatically. The file contents are still fully recoverable with your password — only the names are lost.

> **Security note:** The manifest stores filenames in plain text. If you want the filenames themselves to be secret, keep the manifest in a safe location separate from the encrypted files, or delete it and track the names yourself.

---

## 📝 File Logging

CryptoGraphy can write a timestamped audit log to a file alongside the application.

- Enable it by ticking the **Enable File Logging** checkbox in the app.
- Logs are written to `cryptography.log` in the same folder as the app.
- Each log entry includes: timestamp, log level (INFO / WARNING / ERROR), and message.
- File logging is disabled by default — enable it when you want a record of operations.

---

## 🔧 Troubleshooting

**"No module named cryptography" or "No module named PyQt6"**
→ Run `pip install -r requirements.txt` and try again.

**"Invalid decryption key" error**
→ The password you entered does not match the one used to encrypt the file. Check for typos — the password field is case-sensitive.

**Files processed but names not restored after decryption**
→ The manifest file (`.cg_manifest.json`) is missing from the folder. The file contents are still correctly decrypted — only automatic filename restoration is not possible without the manifest.

**App does not start on Windows**
→ Make sure you are on Windows 10 or newer. Try running `python CryptoGraphy_V1.py` from a terminal to see the error.

**"Permission denied" when processing a file**
→ The file may be open in another application, or you may not have write permission for that folder. Close any apps using the file and try again.

**A file says "failed" in the summary**
→ Check the log panel for the specific error. Common causes: file is open/locked, wrong password, or insufficient disk space.

**The app encrypted itself**
→ This should not happen — the app has a self-exclusion list. If it did, please open a GitHub Issue with details.

---

## ❓ FAQ

**Q: Can I encrypt any file type?**
A: Yes — any file: documents, images, videos, archives, code files, databases, etc. CryptoGraphy treats all files as raw bytes.

**Q: What happens if I run Encrypt twice on the same file?**
A: You get double-encrypted data. Decrypt twice (with the same password) to recover the original. This is not recommended — use it once per file.

**Q: Is the encryption reversible if I forget my password?**
A: No. There is no backdoor or password recovery. The security of the encryption depends entirely on the password being secret. Store your password in a password manager.

**Q: Can I open encrypted files on another computer?**
A: Yes — copy both the encrypted files and the `.cg_manifest.json` to the other computer, install CryptoGraphy, enter your password, and decrypt.

**Q: Does encrypting a file change its size?**
A: Yes, slightly. Fernet adds a small overhead (~100 bytes + base64 expansion). AES-256-GCM adds ~32 bytes (magic + nonce + GCM tag). For large files this is negligible.

**Q: Is `pywin32` required?**
A: No, it is optional. On Windows, it enables correct handling of hidden file attributes. The app works fully without it.

**Q: Does the app send any data over the internet?**
A: No. CryptoGraphy has no network functionality. It is 100% offline.

---

## 🔒 Security Notes

- **Key derivation:** PBKDF2-HMAC-SHA256 with 100,000 iterations makes dictionary and brute-force attacks computationally expensive.
- **Authentication:** Both algorithms (Fernet and AES-256-GCM) include authentication — if even one byte of the encrypted file is modified, decryption will fail with an error rather than producing corrupted output silently.
- **No plaintext storage:** Your password is never stored anywhere on disk. It exists only in memory while the app is running.
- **Random nonces:** AES-256-GCM uses a fresh 12-byte random nonce for every encryption operation, preventing nonce reuse.
- **The manifest is not encrypted** by default. If the manifest's content (original filenames) is sensitive, keep it separate from the encrypted files.

---

## 📬 Contact & Support

- **Telegram:** [@Sparky2273](https://t.me/Sparky2273)
- **Email:** mhashemi6699@gmail.com
- **Bug Reports & Feature Requests:** [Open a GitHub Issue](../../issues)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by SPARKS**

*Your files. Your keys. Your privacy.*

</div>
