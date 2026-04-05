#!/usr/bin/env python3
import requests

# 1. Get encrypted flag
r = requests.get("https://aes.cryptohack.org/block_cipher_starter/encrypt_flag/")
ct = r.json()["ciphertext"]

# 2. Decrypt it using the server's own decrypt endpoint
r = requests.get(f"https://aes.cryptohack.org/block_cipher_starter/decrypt/{ct}/")
pt = bytes.fromhex(r.json()["plaintext"])
print(pt.decode())
# crypto{bl0ck_c1ph3r5_4r3_f457_!}
