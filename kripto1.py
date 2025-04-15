import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# --- Vigenère Cipher ---
def vigenere_encrypt(plaintext, key):
    encrypted = []
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted.append(encrypted_char)
            key_index += 1
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted.append(decrypted_char)
            key_index += 1
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# --- AES ---
def get_aes_key(key):
    return hashlib.sha256(key.encode()).digest()

def aes_encrypt(text, key):
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(base64_text, key):
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(base64_text))
    return unpad(decrypted, AES.block_size).decode()

# --- Caesar Cipher ---
def caesar_encrypt(text, key):
    shift = len(key)
    result = ""
    for char in text:
        result += chr((ord(char) + shift) % 256)
    return result

def caesar_decrypt(text, key):
    shift = len(key)
    result = ""
    for char in text:
        result += chr((ord(char) - shift) % 256)
    return result

# --- Streamlit UI ---
st.title("🔐 Aplikasi Enkripsi & Dekripsi 3 Lapisan (Vigenère → AES → Caesar)")

uploaded_file = st.file_uploader("📂 Upload file (.txt)", type=["txt"])
key = st.text_input("🔑 Masukkan Kunci (Digunakan untuk semua lapisan)")
mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"])

if uploaded_file and key:
    content = uploaded_file.read().decode('utf-8')

    if st.button("🚀 Proses Sekarang"):
        try:
            if mode == "Enkripsi":
                step1 = vigenere_encrypt(content, key)
                step2 = aes_encrypt(step1, key)
                result = caesar_encrypt(step2, key)
                st.success("✅ Enkripsi Berhasil!")
            else:
                step1 = caesar_decrypt(content, key)
                step2 = aes_decrypt(step1, key)
                result = vigenere_decrypt(step2, key)
                st.success("✅ Dekripsi Berhasil!")

            st.text_area("📄 Hasil:", result, height=200)
            st.download_button("⬇️ Download Hasil", data=result, file_name="output.txt", mime="text/plain")
        except Exception as e:
            st.error(f"❌ Terjadi kesalahan: {e}")
