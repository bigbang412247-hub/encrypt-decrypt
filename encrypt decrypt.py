#!/usr/bin/env python3
"""
Fixed and fully functional Encrypt/Decrypt GUI using Fernet symmetric encryption with password-derived key.
Requirements:
  pip install cryptography

Features:
 - Encrypt / Decrypt text
 - Encrypt / Decrypt files
 - Password-based key derivation (PBKDF2HMAC + random salt)
 - Shows errors clearly and handles invalid password/data
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64

SALT_SIZE = 16
KDF_ITERS = 390000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(data)
    return salt + token


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if len(blob) < SALT_SIZE:
        raise ValueError("Encrypted data is too short.")
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    key = derive_key(password, salt)
    return Fernet(key).decrypt(token)


class EncryptorApp:
    def __init__(self, root):
        root.title("Encrypt/Decrypt UI")
        root.geometry("800x600")

        tk.Label(root, text="Input:").pack(anchor='w', padx=8, pady=(8,0))
        self.txt_in = scrolledtext.ScrolledText(root, height=10)
        self.txt_in.pack(fill='both', padx=8)

        pw_frame = tk.Frame(root)
        pw_frame.pack(fill='x', padx=8, pady=6)
        tk.Label(pw_frame, text="Password:").pack(side='left')
        self.ent_password = tk.Entry(pw_frame, show='*')
        self.ent_password.pack(side='left', fill='x', expand=True, padx=(6,6))
        self.show_pw_var = tk.BooleanVar(value=False)
        tk.Checkbutton(pw_frame, text='Show', variable=self.show_pw_var, command=self._toggle_pw).pack(side='left')

        btn_frame = tk.Frame(root)
        btn_frame.pack(fill='x', padx=8)
        tk.Button(btn_frame, text='Encrypt Text', command=self.encrypt_text).pack(side='left')
        tk.Button(btn_frame, text='Decrypt Text', command=self.decrypt_text).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Encrypt File', command=self.encrypt_file).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Decrypt File', command=self.decrypt_file).pack(side='left', padx=6)

        tk.Label(root, text="Output:").pack(anchor='w', padx=8, pady=(8,0))
        self.txt_out = scrolledtext.ScrolledText(root, height=12)
        self.txt_out.pack(fill='both', padx=8, pady=(0,8))

        self.status = tk.Label(root, text="Ready", anchor='w')
        self.status.pack(fill='x', side='bottom')

    def _toggle_pw(self):
        self.ent_password.config(show='' if self.show_pw_var.get() else '*')

    def _get_password(self) -> str:
        pw = self.ent_password.get()
        if not pw:
            raise ValueError("Password cannot be empty.")
        return pw

    def encrypt_text(self):
        try:
            data = self.txt_in.get('1.0', 'end-1c').encode()
            if not data:
                messagebox.showinfo("Empty Input", "Please enter text to encrypt.")
                return
            pw = self._get_password()
            blob = encrypt_bytes(data, pw)
            b64 = base64.urlsafe_b64encode(blob).decode()
            self.txt_out.delete('1.0', 'end')
            self.txt_out.insert('1.0', b64)
            self.status.config(text='Text encrypted successfully.')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.status.config(text='Error encrypting text.')

    def decrypt_text(self):
        try:
            raw = self.txt_in.get('1.0', 'end-1c').strip()
            if not raw:
                messagebox.showinfo('Empty Input', 'Please enter encrypted text.')
                return
            pw = self._get_password()
            blob = base64.urlsafe_b64decode(raw.encode())
            plain = decrypt_bytes(blob, pw)
            self.txt_out.delete('1.0', 'end')
            self.txt_out.insert('1.0', plain.decode(errors='ignore'))
            self.status.config(text='Text decrypted successfully.')
        except InvalidToken:
            messagebox.showerror('Error', 'Invalid password or corrupted data.')
            self.status.config(text='Decryption failed.')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.status.config(text='Error decrypting text.')

    def encrypt_file(self):
        try:
            path = filedialog.askopenfilename(title='Select file to encrypt')
            if not path: return
            pw = self._get_password()
            with open(path, 'rb') as f:
                data = f.read()
            blob = encrypt_bytes(data, pw)
            save_path = filedialog.asksaveasfilename(title='Save encrypted file as', defaultextension='.enc')
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(blob)
                messagebox.showinfo('Saved', f'Encrypted file saved: {save_path}')
                self.status.config(text=f'Encrypted file saved: {save_path}')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.status.config(text='Error encrypting file.')

    def decrypt_file(self):
        try:
            path = filedialog.askopenfilename(title='Select encrypted file')
            if not path: return
            pw = self._get_password()
            with open(path, 'rb') as f:
                blob = f.read()
            plain = decrypt_bytes(blob, pw)
            save_path = filedialog.asksaveasfilename(title='Save decrypted file as')
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(plain)
                messagebox.showinfo('Saved', f'Decrypted file saved: {save_path}')
                self.status.config(text=f'Decrypted file saved: {save_path}')
        except InvalidToken:
            messagebox.showerror('Error', 'Invalid password or corrupted data.')
            self.status.config(text='Decryption failed.')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.status.config(text='Error decrypting file.')


if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
