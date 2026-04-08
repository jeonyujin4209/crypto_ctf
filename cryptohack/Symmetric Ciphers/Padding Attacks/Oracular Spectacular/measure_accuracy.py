#!/usr/bin/env python3
"""Measure per-byte accuracy WITHOUT cascade by testing each byte independently."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os, sys, time

rng = SystemRandom()
HEX_BYTES = [ord(c) for c in '0123456789abcdef']


class LocalOracle:
    def __init__(self):
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return (iv + ct).hex()

    def check_padding(self, ct_hex):
        ct_raw = bytes.fromhex(ct_hex)
        iv, ct = ct_raw[:16], ct_raw[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
            good = True
        except ValueError:
            good = False
        self.query_count += 1
        return good ^ (rng.random() > 0.4)


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def find_byte(oracle_fn, target, inter, pos, prev_byte, budget):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    schedule = [(12, 8), (8, 4), (10, 2)]
    for qpa, keep in schedule:
        n_active = len(active)
        if n_active <= keep:
            break
        for idx in active:
            for _ in range(qpa):
                if used >= budget:
                    break
                r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
                tc[idx] += int(r)
                nc[idx] += 1
                used += 1
        active.sort(key=lambda i: tc[i] / max(1, nc[i]))
        active = active[:keep]

    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            tc[idx] += int(r)
            nc[idx] += 1
            used += 1

    active.sort(key=lambda i: tc[i] / max(1, nc[i]))
    return cands[active[0]], used


# Test byte 15 accuracy (NO cascade dependency)
N = 500
budget = 370
correct_15 = 0

print(f"Testing byte 15 accuracy ({N} trials, budget={budget})...")
start = time.time()

for trial in range(N):
    oracle = LocalOracle()
    ct_hex = oracle.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    inter = [0] * 16
    best, _ = find_byte(oracle.check_padding, c2, inter, 15, c1[15], budget)
    pt = best ^ c1[15]
    actual = ord(oracle.message[31])

    if pt == actual:
        correct_15 += 1

elapsed = time.time() - start
print(f"Byte 15: {correct_15}/{N} = {100*correct_15/N:.1f}% ({elapsed:.1f}s)")

# Test byte 14 accuracy WITH correct byte 15 (measures SH accuracy, not cascade)
correct_14 = 0
print(f"\nTesting byte 14 accuracy with CORRECT byte 15 ({N} trials)...")
start = time.time()

for trial in range(N):
    oracle = LocalOracle()
    ct_hex = oracle.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    # Use CORRECT intermediate for byte 15
    actual_inter15 = ord(oracle.message[31]) ^ c1[15]
    inter = [0] * 16
    inter[15] = actual_inter15

    best, _ = find_byte(oracle.check_padding, c2, inter, 14, c1[14], budget)
    pt = best ^ c1[14]
    actual = ord(oracle.message[30])

    if pt == actual:
        correct_14 += 1

elapsed = time.time() - start
print(f"Byte 14 (with correct 15): {correct_14}/{N} = {100*correct_14/N:.1f}% ({elapsed:.1f}s)")

# Test byte 14 accuracy WITH WRONG byte 15 (simulates cascade break)
correct_14_cascade = 0
print(f"\nTesting byte 14 accuracy with WRONG byte 15 ({N} trials)...")
start = time.time()

for trial in range(N):
    oracle = LocalOracle()
    ct_hex = oracle.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    # Use WRONG intermediate for byte 15
    actual_inter15 = ord(oracle.message[31]) ^ c1[15]
    inter = [0] * 16
    inter[15] = actual_inter15 ^ 0x01  # deliberately wrong

    best, _ = find_byte(oracle.check_padding, c2, inter, 14, c1[14], budget)
    pt = best ^ c1[14]
    actual = ord(oracle.message[30])

    if pt == actual:
        correct_14_cascade += 1

elapsed = time.time() - start
print(f"Byte 14 (with WRONG 15): {correct_14_cascade}/{N} = {100*correct_14_cascade/N:.1f}% (expected ~6.25%)")
