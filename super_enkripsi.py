import base64
import mysql.connector
import streamlit as st

def caesar_encrypt(teks, shift):
    hasil = ""
    for i in range(len(teks)):
        char = teks[i]
        if char.isupper():
            hasil += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            hasil += chr((ord(char) + shift - 97) % 26 + 97)
        elif char == ' ':
            hasil += ' '
        else:
            hasil += char
    return hasil

def xor_encrypt(teks, kunci):
    hasil = ''.join(chr(ord(c) ^ ord(kunci[i % len(kunci)])) for i, c in enumerate(teks))
    return base64.b64encode(hasil.encode()).decode()

def super_encrypt(teks):
    # Step 1: Caesar Cipher
    kunci = "KriptografiAsik"
    caesar_shift = ord(kunci[0]) % 26
    langkah1 = caesar_encrypt(teks, caesar_shift)
    
    # Step 2: XOR Cipher
    langkah2 = xor_encrypt(langkah1, kunci)
    hasil = langkah2
    return hasil

def xor_decrypt(teks, kunci):
    teks = base64.b64decode(teks).decode()
    hasil = ''.join(chr(ord(c) ^ ord(kunci[i % len(kunci)])) for i, c in enumerate(teks))
    return hasil

def caesar_decrypt(teks, shift):
    return caesar_encrypt(teks, -shift)

def super_decrypt(teks):
    kunci = "KriptografiAsik"
    langkah1 = xor_decrypt(teks, kunci)

    caesar_shift = ord(kunci[0]) % 26
    langkah2 = caesar_decrypt(langkah1, caesar_shift)
    hasil = langkah2
    return hasil



