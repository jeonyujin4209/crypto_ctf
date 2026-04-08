#!/usr/bin/env python3
"""Debug: trace the sequential halving for one full block."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os, sys

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


def find_byte_debug(oracle_fn, target, inter, pos, prev_byte, budget, actual_inter=None):
    """Sequential halving with debug output."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]

    tc = [0] * 16
    nc = [0] * 16
    active = list(range(16))
    used = 0

    correct_idx = None
    if actual_inter is not None:
        for i, c in enumerate(cands):
            if c == actual_inter:
                correct_idx = i
                break

    for rnd in range(3):
        n_active = len(active)
        if n_active <= 2:
            break

        remaining = budget - used
        remaining_rounds = 4 - rnd
        qpa = max(7, remaining // (n_active * remaining_rounds))

        for idx in active:
            for _ in range(qpa):
                if used >= budget:
                    break
                r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
                tc[idx] += int(r)
                nc[idx] += 1
                used += 1

        keep = max(2, n_active // 2)
        active.sort(key=lambda i: tc[i] / max(1, nc[i]))
        active = active[:keep]

        correct_survived = correct_idx in active if correct_idx is not None else "?"
        rates = [(i, tc[i]/max(1,nc[i])) for i in active]
        print(f"    Rnd {rnd}: qpa={qpa} active={len(active)} "
              f"correct_survived={correct_survived}")

    # Final duel
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            tc[idx] += int(r)
            nc[idx] += 1
            used += 1

    active.sort(key=lambda i: tc[i] / max(1, nc[i]))
    best = cands[active[0]]

    if correct_idx is not None:
        final_rates = {i: tc[i]/nc[i] for i in active}
        correct_rate = tc[correct_idx]/nc[correct_idx] if nc[correct_idx] > 0 else -1
        print(f"    Final: best_rate={tc[active[0]]/nc[active[0]]:.3f} "
              f"correct_rate={correct_rate:.3f} "
              f"correct_in_final={correct_idx in active}")

    return best, used


# Run debug for one full block
oracle = LocalOracle()
ct_hex = oracle.get_ct()
ct_b = bytes.fromhex(ct_hex)
iv = list(ct_b[:16])
c1 = list(ct_b[16:32])
c2 = list(ct_b[32:48])

msg = oracle.message
print(f"Message: {msg}")
print(f"Block 2 (chars 16-31): {msg[16:32]}")

# Compute actual intermediates for block 2
# I[pos] = P2[pos] ^ C1[pos]
actual_inters = [ord(msg[16+i]) ^ c1[i] for i in range(16)]

inter2 = [0] * 16
correct_count = 0
cascade_broken = False

for pos in range(15, -1, -1):
    actual_inter = actual_inters[pos]
    print(f"\nByte pos={pos:2d} (actual='{msg[16+pos]}' inter=0x{actual_inter:02x}):")

    best, used = find_byte_debug(
        oracle.check_padding, c2, inter2, pos, c1[pos], 370, actual_inter)
    inter2[pos] = best

    pt_byte = best ^ c1[pos]
    actual_byte = ord(msg[16+pos])
    ok = pt_byte == actual_byte
    if ok:
        correct_count += 1
    else:
        cascade_broken = True

    print(f"  Result: got=0x{pt_byte:02x}('{chr(pt_byte) if 32<=pt_byte<127 else '?'}') "
          f"actual=0x{actual_byte:02x}('{chr(actual_byte)}') "
          f"{'OK' if ok else 'WRONG'} "
          f"{'[CASCADE BROKEN]' if cascade_broken and not ok else ''}")

print(f"\nBlock 2: {correct_count}/16 correct, total queries: {oracle.query_count}")
