"""Test different screen query counts for the adaptive top-2 approach.
This time testing with ACTUAL oracle, not coin simulation."""

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


def find_byte_adaptive(challenge, target, inter, pos, prev_byte, budget, screen_q=2, top_k=2):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    counts = [0] * 16
    used = 0

    sq = min(screen_q, budget // 16)
    for idx in range(16):
        for _ in range(sq):
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            counts[idx] += 1
            used += 1

    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for target_idx in sorted_idx[:top_k]:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[target_idx]))
            llr[target_idx] += LOG_P if r else -LOG_P
            counts[target_idx] += 1
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], used


def test_accuracy(budget, screen_q, top_k, n_trials=1000):
    """Test per-byte accuracy with correct intermediates."""
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
        best, _ = find_byte_adaptive(ch, c2, true_inter, pos, c1[pos], budget, screen_q, top_k)
        if best == true_inter[pos]:
            correct += 1
    return correct / n_trials


# Test various configurations
budget = 125
print(f"Budget={budget}")
print(f"{'Config':30s} {'Accuracy':>10s} {'P(32)':>10s}")

configs = [
    (2, 2, "screen=2, top=2"),
    (3, 2, "screen=3, top=2"),
    (4, 2, "screen=4, top=2"),
    (5, 2, "screen=5, top=2"),
    (6, 2, "screen=6, top=2"),
    (7, 2, "screen=7, top=2"),
    (3, 3, "screen=3, top=3"),
    (4, 3, "screen=4, top=3"),
    (5, 3, "screen=5, top=3"),
    (4, 4, "screen=4, top=4"),
    (5, 4, "screen=5, top=4"),
]

for sq, tk, name in configs:
    acc = test_accuracy(budget, sq, tk)
    print(f"  {name:30s} {100*acc:8.1f}%  {100*acc**32:8.3f}%")

# Also test at budget=370 (single CT)
print(f"\nBudget=370")
for sq, tk, name in [(3, 2, "screen=3, top=2"), (5, 2, "screen=5, top=2"),
                      (7, 2, "screen=7, top=2"), (5, 3, "screen=5, top=3")]:
    acc = test_accuracy(370, sq, tk)
    print(f"  {name:30s} {100*acc:8.1f}%  {100*acc**32:8.3f}%")
