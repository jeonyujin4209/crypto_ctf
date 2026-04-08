#!/usr/bin/env python3
import requests

# CBC encrypt with random IV, ECB decrypt available
# CBC: C_i = E(P_i ^ C_{i-1}), C_0 = IV
# ECB decrypt: D(C_i) = P_i ^ C_{i-1}
# So: P_i = D(C_i) ^ C_{i-1}

r = requests.get("https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/").json()
ct = bytes.fromhex(r["ciphertext"])

blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
iv = blocks[0]
cipher_blocks = blocks[1:]

plaintext = b""
prev = iv
for cb in cipher_blocks:
    r = requests.get(f"https://aes.cryptohack.org/ecbcbcwtf/decrypt/{cb.hex()}/").json()
    dec = bytes.fromhex(r["plaintext"])
    plaintext += bytes(a ^ b for a, b in zip(dec, prev))
    prev = cb

print(plaintext.decode().strip())
# crypto{3cb_5uck5_4v01d_17_!!!!!}
