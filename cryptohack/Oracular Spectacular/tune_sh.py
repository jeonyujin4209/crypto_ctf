#!/usr/bin/env python3
"""Grid search over SH schedules to maximize per-byte accuracy."""

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


def test_schedule(schedule, budget, N=500):
    """Test a SH schedule on byte 15 accuracy."""
    correct = 0
    for _ in range(N):
        oracle = LocalOracle()
        ct_hex = oracle.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])

        pad = 1
        cands = [c1[15] ^ h for h in HEX_BYTES]
        tc = [0] * 16
        nc = [0] * 16
        active = list(range(16))
        used = 0
        inter = [0] * 16

        for qpa, keep in schedule:
            if len(active) <= keep:
                break
            for idx in active:
                for _ in range(qpa):
                    if used >= budget:
                        break
                    r = oracle.check_padding(make_ct(c2, inter, 15, pad, cands[idx]))
                    tc[idx] += int(r)
                    nc[idx] += 1
                    used += 1
            active.sort(key=lambda i: tc[i] / max(1, nc[i]))
            active = active[:keep]

        while used < budget:
            for idx in active:
                if used >= budget:
                    break
                r = oracle.check_padding(make_ct(c2, inter, 15, pad, cands[idx]))
                tc[idx] += int(r)
                nc[idx] += 1
                used += 1

        active.sort(key=lambda i: tc[i] / max(1, nc[i]))
        pt = cands[active[0]] ^ c1[15]
        if pt == ord(oracle.message[31]):
            correct += 1

    return correct / N


# Grid search over schedules
budget = 370
print(f"Grid search over SH schedules (budget={budget}, N=500)")
print(f"{'Schedule':<30s} {'Screen':>7s} {'Final/arm':>9s} {'Accuracy':>8s}")
print("-" * 58)

results = []

# 3-round schedules: 16->8->4->2->1
for r0 in [8, 10, 12, 14, 16, 18, 20]:
    for r1 in [4, 6, 8, 10, 12]:
        for r2 in [4, 6, 8, 10, 12, 15]:
            screen = 16*r0 + 8*r1 + 4*r2
            if screen >= budget - 10:  # need at least 10 for final
                continue
            final_per = (budget - screen) // 2
            if final_per < 3:
                continue
            sched = [(r0, 8), (r1, 4), (r2, 2)]
            acc = test_schedule(sched, budget, N=300)
            tag = f"({r0},{r1},{r2},~{final_per})"
            results.append((acc, tag, sched))
            if acc >= 0.70:
                print(f"{tag:<30s} {screen:>7d} {final_per:>9d} {100*acc:>7.1f}%")

# Also test 2-round: 16->4->2->1
for r0 in [14, 16, 18, 20]:
    for r1 in [8, 10, 12, 15, 20]:
        screen = 16*r0 + 4*r1
        if screen >= budget - 10:
            continue
        final_per = (budget - screen) // 2
        sched = [(r0, 4), (r1, 2)]
        acc = test_schedule(sched, budget, N=300)
        tag = f"2rnd({r0},{r1},~{final_per})"
        results.append((acc, tag, sched))
        if acc >= 0.70:
            print(f"{tag:<30s} {screen:>7d} {final_per:>9d} {100*acc:>7.1f}%")

# Sort and show top results
results.sort(key=lambda x: -x[0])
print(f"\n{'='*58}")
print(f"Top 10 schedules:")
for acc, tag, sched in results[:10]:
    screen = sum(q*n for q, n in [(sched[0][0],16)] + [(s[0], {8:8,4:4,2:2}.get(s[1],4)) for s in sched[1:]])
    # Just recalculate
    s = 0
    arms = 16
    for qpa, keep in sched:
        s += arms * qpa
        arms = keep
    final_per = (budget - s) // 2
    print(f"  {tag:<30s} acc={100*acc:.1f}% final/arm={final_per}")
