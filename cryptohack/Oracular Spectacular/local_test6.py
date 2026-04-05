"""Single CT, 370 queries/byte, UNIFORM allocation. Test per-byte accuracy."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os
import sys
import time
from collections import Counter

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']


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


def find_byte_uniform(challenge, target, inter, pos, prev_byte, budget):
    """Pure uniform allocation across 16 candidates."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    scores = [0] * 16
    q_each = budget // 16

    for idx in range(16):
        for _ in range(q_each):
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)

    best = max(range(16), key=lambda i: scores[i])
    return cands[best], q_each * 16


def recover_block(challenge, target, prev, budget_per_byte):
    inter = [0] * 16
    total_used = 0
    for pos in range(15, -1, -1):
        best, used = find_byte_uniform(challenge, target, inter, pos, prev[pos], budget_per_byte)
        inter[pos] = best
        total_used += used
    return inter, total_used


def run_test(budget_per_byte=368):
    ch = LocalChallenge()
    actual_msg = ch.message
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    ch.query_count = 0
    i2, q2 = recover_block(ch, c2, c1, budget_per_byte)
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])
    i1, q1 = recover_block(ch, c1, iv, budget_per_byte)
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])

    recovered = (pt1 + pt2).decode('ascii', 'replace')
    wrong = sum(1 for i in range(32) if recovered[i] != actual_msg[i])
    return recovered == actual_msg, wrong, ch.query_count


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    successes = 0
    wrongs = []

    for t in range(1, n_trials + 1):
        ok, wrong, q = run_test()
        if ok:
            successes += 1
        wrongs.append(wrong)
        if t % 20 == 0 or t == n_trials:
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) avg_wrong={sum(wrongs)/len(wrongs):.1f}")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    print(f"Wrong dist: {dict(sorted(dist.items()))}")
