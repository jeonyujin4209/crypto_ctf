"""
Final approach: Single CT, adaptive top-2 with screen_q=2.
Budget: 370 queries per byte (370 × 32 = 11840 < 12000).
Expected success rate: ~1.3% per trial.
Retry until success.
"""

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
HEX_LIST = [ord(c) for c in '0123456789abcdef']
HEX_SET = set(HEX_LIST)
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


def find_byte(challenge, target, inter, pos, prev_byte, budget):
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


def recover_block(challenge, target, prev, budget_per_byte):
    inter = [0] * 16
    total_used = 0
    for pos in range(15, -1, -1):
        best, used = find_byte(challenge, target, inter, pos, prev[pos], budget_per_byte)
        inter[pos] = best
        total_used += used
    return inter, total_used


def run_test(budget_per_byte=370):
    ch = LocalChallenge()
    actual_msg = ch.message
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    ch.query_count = 0

    i2, _ = recover_block(ch, c2, c1, budget_per_byte)
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])

    i1, _ = recover_block(ch, c1, iv, budget_per_byte)
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])

    recovered = (pt1 + pt2).decode('ascii', 'replace')
    wrong = sum(1 for i in range(32) if recovered[i] != actual_msg[i])
    return recovered == actual_msg, wrong, ch.query_count


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 500

    successes = 0
    wrongs = []
    total_start = time.time()

    for t in range(1, n_trials + 1):
        ok, wrong, q = run_test(370)
        if ok:
            successes += 1
        wrongs.append(wrong)
        if t % 100 == 0 or t == n_trials:
            elapsed = time.time() - total_start
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f} "
                  f"time={elapsed:.0f}s ({elapsed/t:.2f}s/trial)")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    print(f"Wrong dist: {dict(sorted(dist.items()))}")
