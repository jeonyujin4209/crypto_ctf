#!/usr/bin/env python3
import requests

# IV = KEY (fatal mistake)
# Encrypt: CBC with KEY as IV
# Decrypt: if not valid UTF-8, returns hex of decrypted plaintext
#
# Attack: send C1 || 0x00*16 || C1
# P1 = D(C1) ^ KEY  (IV=KEY)
# P2 = D(0x00*16) ^ C1
# P3 = D(C1) ^ 0x00*16 = D(C1)
# KEY = P1 ^ P3

r = requests.get(f"https://aes.cryptohack.org/lazy_cbc/encrypt/{'00'*16}/").json()
c1 = bytes.fromhex(r["ciphertext"])[:16]

crafted = c1 + b"\x00" * 16 + c1
r = requests.get(f"https://aes.cryptohack.org/lazy_cbc/receive/{crafted.hex()}/").json()

dec = bytes.fromhex(r["error"].split(": ")[1])
p1, p3 = dec[:16], dec[32:48]
key = bytes(a ^ b for a, b in zip(p1, p3))

r = requests.get(f"https://aes.cryptohack.org/lazy_cbc/get_flag/{key.hex()}/").json()
print(bytes.fromhex(r["plaintext"]).decode())
# crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}
