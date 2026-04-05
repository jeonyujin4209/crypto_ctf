"""Test screen_q=3 vs screen_q=2."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
import sys
import time
from collections import Counter

rng_local = SystemRandom()
LOG_P = math.log(0.4 / 0.6)
HEX_CHARS = [ord(c) for c in '0123456789abcdef']


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


def find_byte(oracle_fn, target, inter, pos, prev_byte, budget, screen_q=2):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_CHARS]
    llr = [0.0] * 16
    used = 0

    for idx in range(16):
        for _ in range(screen_q):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], used


def run_trial(screen_q=2):
    ch = LocalChallenge()
    ct_hex = ch.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    ch.query_count = 0

    def oracle(ct_hex):
        return ch.check_padding(ct_hex)

    for target, prev, bytes_after in [(c2, c1, 16), (c1, iv, 0)]:
        inter = [0] * 16
        for pos in range(15, -1, -1):
            remaining_bytes = pos + 1 + bytes_after
            remaining_q = 11950 - ch.query_count
            budget = min(remaining_q // max(1, remaining_bytes), 400)
            budget = max(budget, 100)
            best, _ = find_byte(oracle, target, inter, pos, prev[pos], budget, screen_q)
            inter[pos] = best

        if bytes_after == 16:
            pt2 = bytes([inter[i] ^ prev[i] for i in range(16)])
        else:
            pt1 = bytes([inter[i] ^ prev[i] for i in range(16)])

    recovered = (pt1 + pt2).decode('ascii', 'replace')
    wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])
    return recovered == ch.message, wrong, ch.query_count


n_trials = 3000
for sq in [2, 3]:
    successes = 0
    wrongs = []
    t0 = time.time()
    for t in range(1, n_trials + 1):
        ok, wrong, q = run_trial(sq)
        if ok: successes += 1
        wrongs.append(wrong)
    elapsed = time.time() - t0
    print(f"screen_q={sq}: {successes}/{n_trials} ({100*successes/n_trials:.2f}%) "
          f"avg_wrong={sum(wrongs)/len(wrongs):.1f} time={elapsed:.0f}s")
