"""Precisely measure per-byte accuracy at budget=375 with true intermediates, real oracle."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
import random

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']
LOG_P = math.log(0.4 / 0.6)


class LocalChallenge:
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
        ct = bytes.fromhex(ct_hex)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
        except ValueError:
            good = False
        else:
            good = True
        self.query_count += 1
        return good ^ (rng_local.random() > 0.4)


def make_ct(target_block, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target_block)).hex()


def find_byte(oracle_fn, target_block, inter, pos, prev_byte, budget):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    # Screen
    screen_q = 2
    for idx in range(16):
        for _ in range(screen_q):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive top-2
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best]


n_trials = 5000
budget = 375
correct = 0

for _ in range(n_trials):
    ch = LocalChallenge()
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])
    cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
    true_inter = list(cipher_ecb.decrypt(bytes(c2)))

    pos = random.randint(0, 15)
    best = find_byte(ch.check_padding, c2, true_inter, pos, c1[pos], budget)
    if best == true_inter[pos]:
        correct += 1

acc = correct / n_trials
print(f"Per-byte accuracy (true inters, budget={budget}): {correct}/{n_trials} = {100*acc:.2f}%")
print(f"P(16 bytes correct, no cascade): {100*acc**16:.2f}%")
print(f"P(32 bytes correct, no cascade): {100*acc**32:.4f}%")
