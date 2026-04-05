"""Test find_byte with TRUE intermediates to get actual per-byte accuracy."""

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


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def find_byte_adaptive(challenge, target, inter, pos, prev_byte, budget):
    """Adaptive top-2 with screen_q=2."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    # Screen: 2 queries per candidate = 32
    for idx in range(16):
        for _ in range(2):
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive: focus on top 2
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], used


# Test per-byte accuracy with TRUE intermediates
n_trials = 2000
budget = 370
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
    best, _ = find_byte_adaptive(ch, c2, true_inter, pos, c1[pos], budget)
    if best == true_inter[pos]:
        correct += 1

acc = correct / n_trials
print(f"Per-byte accuracy (true inters, budget={budget}): {correct}/{n_trials} = {100*acc:.1f}%")
print(f"P(32 correct): {100*acc**32:.3f}%")
