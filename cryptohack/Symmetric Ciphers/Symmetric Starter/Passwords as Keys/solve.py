#!/usr/bin/env python3
import requests, hashlib
from Crypto.Cipher import AES

# Get encrypted flag
r = requests.get("https://aes.cryptohack.org/passwords_as_keys/encrypt_flag/")
ct = bytes.fromhex(r.json()["ciphertext"])

# Download wordlist
r2 = requests.get("https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words")
words = r2.text.strip().split("\n")

# Brute force: md5(word) as AES key
for w in words:
    key = hashlib.md5(w.strip().encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    if pt.startswith(b"crypto{"):
        print(f"Password: {w.strip()}")
        print(f"Flag: {pt.decode()}")
        break
# Password: bluebell
# crypto{k3y5__r__n07__p455w0rdz?}
