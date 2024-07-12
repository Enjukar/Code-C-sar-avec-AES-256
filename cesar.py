import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# Chiffrement de César
def caesar_cipher(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

# Chiffrement AES-256
def encrypt_aes(key, plaintext):
    key = hashlib.sha256(key.encode()).digest()  # Hash the key to get a 256-bit key
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def decrypt_aes(key, ciphertext):
    key = hashlib.sha256(key.encode()).digest()  # Hash the key to get a 256-bit key
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

# Interface utilisateur
def encrypt_text():
    text = entry_text.get("1.0", tk.END).strip()
    shift = int(entry_shift.get())
    aes_key = entry_aes_key.get()

    caesar_encrypted = caesar_cipher(text, shift)
    aes_encrypted = encrypt_aes(aes_key, caesar_encrypted)
    
    result_text.set(aes_encrypted)

def decrypt_text():
    aes_key = entry_aes_key.get()
    aes_encrypted = entry_text.get("1.0", tk.END).strip()
    shift = int(entry_shift.get())

    try:
        caesar_encrypted = decrypt_aes(aes_key, aes_encrypted)
        text = caesar_cipher(caesar_encrypted, -shift)
        result_text.set(text)
    except Exception as e:
        messagebox.showerror("Erreur", str(e))

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("Chiffrement César et AES-256")

tk.Label(root, text="Texte à chiffrer / déchiffrer:").grid(row=0, column=0, padx=10, pady=10)
entry_text = tk.Text(root, height=10, width=50)
entry_text.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Décalage (César):").grid(row=1, column=0, padx=10, pady=10)
entry_shift = tk.Entry(root)
entry_shift.grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Clé AES:").grid(row=2, column=0, padx=10, pady=10)
entry_aes_key = tk.Entry(root)
entry_aes_key.grid(row=2, column=1, padx=10, pady=10)

tk.Button(root, text="Chiffrer", command=encrypt_text).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Déchiffrer", command=decrypt_text).grid(row=3, column=1, padx=10, pady=10)

result_text = tk.StringVar()
tk.Label(root, text="Résultat:").grid(row=4, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=result_text, width=50).grid(row=4, column=1, padx=10, pady=10)

root.mainloop()
