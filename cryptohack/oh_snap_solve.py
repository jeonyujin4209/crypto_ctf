#!/usr/bin/env python3
import requests
from Crypto.Cipher import ARC4

s = requests.Session()
base = "https://aes.cryptohack.org/oh_snap/send_cmd"

def get_keystream(nonce_hex, length=1):
    ct_hex = "00" * length
    r = s.get(f"{base}/{ct_hex}/{nonce_hex}/").json()
    if "error" in r:
        h = r["error"].split(": ")[1]
        return bytes.fromhex(h)
    return None

# FMS attack on RC4
# key = nonce + FLAG
# Use nonce = [A, 0xFF] so key[0]=A, key[1]=0xFF, key[2+i]=FLAG[i]
# After partial KSA with known bytes, guess unknown key byte

known_flag = list(b"crypto{")

for target in range(len(known_flag), 50):
    A = target + 2
    nonce = bytes([A % 256, 0xFF])

    # Partial KSA with known key prefix
    S = list(range(256))
    j = 0
    known_key = list(nonce) + known_flag[:target]
    for i in range(len(known_key)):
        j = (j + S[i] + known_key[i]) % 256
        S[i], S[j] = S[j], S[i]

    # Get first keystream byte
    ks = get_keystream(nonce.hex(), 1)
    if ks is None:
        print(f"  [{target}] Failed to get keystream")
        continue
    out = ks[0]

    # FMS guess
    S_inv = [0] * 256
    for x in range(256):
        S_inv[S[x]] = x
    guess = (S_inv[out] - j - S[A % 256]) % 256
    known_flag.append(guess)
    c = chr(guess) if 32 <= guess <= 126 else f"\\x{guess:02x}"
    print(f"  [{target}] {c} -> {''.join(chr(b) if 32<=b<=126 else '?' for b in known_flag)}")

    if guess == ord("}"):
        break

flag = bytes(known_flag).decode(errors="replace")
print(f"\nOh SNAP: {flag}")
