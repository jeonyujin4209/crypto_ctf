#!/usr/bin/env python3
"""Compare different strategies for per-byte accuracy."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os, time

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


def strategy_uniform(oracle_fn, target, inter, pos, prev_byte, budget):
    """No elimination. Test all 16 candidates equally. Pick min true count."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    qpa = budget // 16
    tc = [0] * 16
    for i in range(16):
        for _ in range(qpa):
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[i]))
            tc[i] += int(r)
    best = min(range(16), key=lambda i: tc[i])
    return cands[best]


def strategy_sh_heavy_r0(oracle_fn, target, inter, pos, prev_byte, budget):
    """Sequential halving with heavy round 0."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    # Heavy R0: 18/arm. R1: 5/arm. R2: 5/arm. Rest: final.
    schedule = [(18, 8), (5, 4), (5, 2)]
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


def strategy_sh_original(oracle_fn, target, inter, pos, prev_byte, budget):
    """Original SH: 12/8/10/rest."""
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


def strategy_sh_5round(oracle_fn, target, inter, pos, prev_byte, budget):
    """5-round gentle SH: 16->12->8->4->2->1."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    schedule = [(6, 12), (6, 8), (6, 4), (8, 2)]
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


def strategy_adaptive_elim(oracle_fn, target, inter, pos, prev_byte, budget):
    """Successive elimination: eliminate when statistically dominated."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    import math

    while used < budget and len(active) > 1:
        # Query each active candidate once
        for idx in active:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            tc[idx] += int(r)
            nc[idx] += 1
            used += 1

        if len(active) <= 2:
            continue

        # Find current best (lowest true rate)
        rates = [(i, tc[i]/nc[i]) for i in active]
        rates.sort(key=lambda x: x[1])
        best_rate = rates[0][1]
        best_n = nc[rates[0][0]]

        # Confidence bound: eliminate if significantly worse than best
        # Using Hoeffding-style bound
        threshold = math.sqrt(math.log(32 * budget) / (2 * best_n))

        new_active = []
        for i in active:
            rate_i = tc[i] / nc[i]
            if rate_i - best_rate < 2 * threshold:
                new_active.append(i)

        if len(new_active) >= 2:
            active = new_active

    active.sort(key=lambda i: tc[i] / max(1, nc[i]))
    return cands[active[0]]


# Run comparison
N = 500
budget = 370
strategies = {
    'uniform': strategy_uniform,
    'sh_12_8_10': strategy_sh_original,
    'sh_heavy_r0': strategy_sh_heavy_r0,
    'sh_5round': strategy_sh_5round,
    'adaptive_elim': strategy_adaptive_elim,
}

print(f"Comparing strategies on byte 15 (N={N}, budget={budget})")
print(f"{'Strategy':<20s} {'Accuracy':>8s} {'Time':>6s}")
print("-" * 36)

for name, fn in strategies.items():
    correct = 0
    start = time.time()
    for _ in range(N):
        oracle = LocalOracle()
        ct_hex = oracle.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        inter = [0] * 16
        best = fn(oracle.check_padding, c2, inter, 15, c1[15], budget)
        pt = best ^ c1[15]
        if pt == ord(oracle.message[31]):
            correct += 1
    elapsed = time.time() - start
    print(f"{name:<20s} {100*correct/N:7.1f}% {elapsed:5.1f}s")
