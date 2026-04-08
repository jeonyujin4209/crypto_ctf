#!/usr/bin/env python3
"""
Test adaptive top-2 vs SH vs other strategies with N=1000 for reliable measurement.
"""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math, os, time

rng = SystemRandom()
HEX_BYTES = [ord(c) for c in '0123456789abcdef']
LOG_P = math.log(0.4 / 0.6)  # ~-0.405


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


def adaptive_top2(oracle_fn, target, inter, pos, prev_byte, budget, screen_q=2):
    """
    Adaptive top-2: screen all 16 with screen_q queries each,
    then repeatedly query the top-2 by LLR until budget exhausted.
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    llr = [0.0] * 16
    used = 0

    # Screen
    for idx in range(16):
        for _ in range(screen_q):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive: query top-2, re-sort each iteration
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best]


def adaptive_top2_screen4(oracle_fn, target, inter, pos, prev_byte, budget):
    return adaptive_top2(oracle_fn, target, inter, pos, prev_byte, budget, screen_q=4)


def adaptive_top2_screen6(oracle_fn, target, inter, pos, prev_byte, budget):
    return adaptive_top2(oracle_fn, target, inter, pos, prev_byte, budget, screen_q=6)


def sh_best(oracle_fn, target, inter, pos, prev_byte, budget):
    """SH with schedule (12, 8, 10, rest)."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    schedule = [(12, 8), (8, 4), (10, 2)]
    for qpa, keep in schedule:
        if len(active) <= keep:
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
    return cands[active[0]]


def test_byte15(strategy_fn, N=1000, budget=370):
    correct = 0
    for _ in range(N):
        oracle = LocalOracle()
        ct_hex = oracle.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        inter = [0] * 16
        best = strategy_fn(oracle.check_padding, c2, inter, 15, c1[15], budget)
        if (best ^ c1[15]) == ord(oracle.message[31]):
            correct += 1
    return correct / N


# Compare strategies
N = 1000
budget = 370
strategies = {
    'adaptive_top2_s2': lambda o,t,i,p,pb,b: adaptive_top2(o,t,i,p,pb,b,2),
    'adaptive_top2_s4': lambda o,t,i,p,pb,b: adaptive_top2(o,t,i,p,pb,b,4),
    'adaptive_top2_s6': lambda o,t,i,p,pb,b: adaptive_top2(o,t,i,p,pb,b,6),
    'adaptive_top2_s8': lambda o,t,i,p,pb,b: adaptive_top2(o,t,i,p,pb,b,8),
    'sh_12_8_10': sh_best,
}

print(f"Per-byte accuracy on byte 15 (N={N}, budget={budget})")
print(f"{'Strategy':<25s} {'Accuracy':>8s} {'Time':>6s}")
print("-" * 42)

for name, fn in strategies.items():
    start = time.time()
    acc = test_byte15(fn, N, budget)
    elapsed = time.time() - start
    print(f"{name:<25s} {100*acc:7.1f}% {elapsed:5.1f}s")
