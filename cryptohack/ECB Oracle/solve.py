#!/usr/bin/env python3
import requests

# Byte-at-a-time ECB attack
# Server encrypts: pad(user_input || FLAG) in ECB mode
# By controlling padding length, we align the unknown byte at block boundary
# Then brute-force 256 possibilities per byte

s = requests.Session()
base = "https://aes.cryptohack.org/ecb_oracle/encrypt"
block_size = 16
known = b""

for idx in range(50):
    pad_len = block_size - 1 - (len(known) % block_size)
    if pad_len == 0:
        pad_len = block_size
    padding = "41" * pad_len

    r = s.get(f"{base}/{padding}/").json()
    target_block = (pad_len + len(known)) // block_size
    ref_block = r["ciphertext"][target_block*32 : (target_block+1)*32]

    for b in range(32, 127):
        test_hex = padding + (known + bytes([b])).hex()
        r = s.get(f"{base}/{test_hex}/").json()
        if r["ciphertext"][target_block*32 : (target_block+1)*32] == ref_block:
            known += bytes([b])
            break

    if known[-1:] == b"}":
        break

print(known.decode())
# crypto{p3n6u1n5_h473_3cb}
