"""Final local test - matches solve.py algorithm exactly."""

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


def find_byte(oracle_fn, target, inter, pos, prev_byte, budget):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_CHARS]
    llr = [0.0] * 16
    used = 0

    for idx in range(16):
        for _ in range(2):
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


def run_trial():
    ch = LocalChallenge()
    ct_hex = ch.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    ch.query_count = 0

    def oracle(ct_hex):
        return ch.check_padding(ct_hex)

    # Block 2
    inter2 = [0] * 16
    for pos in range(15, -1, -1):
        remaining_bytes = pos + 1 + 16
        remaining_q = 11950 - ch.query_count
        budget = min(remaining_q // max(1, remaining_bytes), 400)
        budget = max(budget, 100)
        best, _ = find_byte(oracle, c2, inter2, pos, c1[pos], budget)
        inter2[pos] = best

    pt2 = bytes([inter2[i] ^ c1[i] for i in range(16)])

    # Block 1
    inter1 = [0] * 16
    for pos in range(15, -1, -1):
        remaining_bytes = pos + 1
        remaining_q = 11950 - ch.query_count
        budget = min(remaining_q // max(1, remaining_bytes), 400)
        budget = max(budget, 100)
        best, _ = find_byte(oracle, c1, inter1, pos, iv[pos], budget)
        inter1[pos] = best

    pt1 = bytes([inter1[i] ^ iv[i] for i in range(16)])

    recovered = (pt1 + pt2).decode('ascii', 'replace')
    wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])
    return recovered == ch.message, wrong, ch.query_count


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    successes = 0
    wrongs = []
    t0 = time.time()

    for t in range(1, n_trials + 1):
        ok, wrong, q = run_trial()
        if ok:
            successes += 1
        wrongs.append(wrong)
        if t % 500 == 0 or t == n_trials:
            elapsed = time.time() - t0
            print(f"After {t:5d}: {successes:3d}/{t} ({100*successes/t:.2f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f} "
                  f"{elapsed:.0f}s ({1000*elapsed/t:.0f}ms/trial)")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.2f}%)")
    print(f"Wrong dist (top): ", end="")
    dist = Counter(wrongs)
    for k in sorted(dist)[:10]:
        print(f"{k}:{dist[k]} ", end="")
    print()
