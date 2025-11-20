# Encrypt-Decrypt Python Tool

A simple and user-friendly Python application for **encrypting and decrypting text and files**. Supports both **CLI** (terminal) and **GUI** usage. Uses **Fernet symmetric encryption** with a password-derived key for secure data handling.

---

## Features

- Encrypt and decrypt **text** via terminal or GUI.
- Encrypt and decrypt **files** securely.
- Password-based key derivation using **PBKDF2HMAC**.
- Base64 output for easy copy/paste of encrypted text.
- Cross-platform Python 3 compatibility with **Tkinter GUI**.
- Lightweight, simple, and beginner-friendly.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/bigbang412247-hub/encrypt-decrypt.git
cd encrypt-decrypt

# Install dependencies
pip install cryptography

# Optional (for GUI)
sudo apt install python3-tk
