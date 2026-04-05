"""
Full end-to-end test with single CT, adaptive top-2.
Budget: 375 queries per byte × 32 bytes = 12000.
Expected ~1.4% success per trial.
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
    """Build modified ciphertext for padding oracle."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target_block)).hex()


def find_byte(oracle_fn, target_block, inter, pos, prev_byte, budget):
    """
    Find intermediate byte at position pos using adaptive top-2.
    oracle_fn: function(ct_hex) -> bool
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    # Screen: 2 queries per candidate
    for idx in range(16):
        for _ in range(2):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive: focus on top 2, re-evaluating each round
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], used


def recover_block(oracle_fn, target_block, prev_block, budget_per_byte):
    """Recover one 16-byte plaintext block."""
    inter = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        best, used = find_byte(oracle_fn, target_block, inter, pos, prev_block[pos], budget_per_byte)
        inter[pos] = best
        total_used += used

    return inter, total_used


def solve(challenge):
    """Main solve function."""
    ct_hex = challenge.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    budget_per_byte = 375  # 375 * 32 = 12000

    # Recover block 2 (last block, includes padding info)
    i2, q2 = recover_block(challenge.check_padding, c2, c1, budget_per_byte)
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])

    # Recover block 1
    i1, q1 = recover_block(challenge.check_padding, c1, iv, budget_per_byte)
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])

    return (pt1 + pt2).decode('ascii', 'replace')


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 1000

    successes = 0
    wrongs = []
    total_start = time.time()

    for t in range(1, n_trials + 1):
        ch = LocalChallenge()
        recovered = solve(ch)
        ok = recovered == ch.message
        wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])

        if ok:
            successes += 1
        wrongs.append(wrong)

        if t % 200 == 0 or t == n_trials:
            elapsed = time.time() - total_start
            avg_w = sum(wrongs)/len(wrongs)
            zero_w = wrongs.count(0)
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) "
                  f"avg_wrong={avg_w:.1f} q={ch.query_count} "
                  f"{elapsed:.0f}s ({elapsed/t:.3f}s/trial)")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    for k in sorted(dist):
        print(f"  {k} wrong: {dist[k]} ({100*dist[k]/n_trials:.1f}%)")
