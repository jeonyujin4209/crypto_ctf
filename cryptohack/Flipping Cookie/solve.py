#!/usr/bin/env python3
import requests

# CBC bit-flipping attack
# Cookie: "admin=False;expiry=..." encrypted with CBC
# P1 = D(C1) ^ IV → flip IV to change plaintext

r = requests.get("https://aes.cryptohack.org/flipping_cookie/get_cookie/").json()
cookie = bytes.fromhex(r["cookie"])
iv = cookie[:16]
ct = cookie[16:]

original = b"admin=False;expi"  # first 16 bytes
target   = b"admin=True\x00;expi"  # \x00 placeholder, semicolon separator

# Flip IV bits: new_iv[i] = iv[i] ^ original[i] ^ target[i]
new_iv = bytes(a ^ b ^ c for a, b, c in zip(iv, original, target))

r = requests.get(f"https://aes.cryptohack.org/flipping_cookie/check_admin/{ct.hex()}/{new_iv.hex()}/").json()
print(r["flag"])
# crypto{4u7h3n71c4710n_15_3553n714l}
