"""
Sequential halving with proper budget allocation.
Round structure: b queries per candidate per round.
16→8→4→2→final
"""

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


def find_byte(challenge, target, inter, pos, prev_byte, budget):
    """Sequential halving: 16→8→4→2→final with b queries per round."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    scores = [0] * 16
    used = 0
    active = list(range(16))

    # Compute b: total = 16b + 8b + 4b + 2*(budget-28b)/2 = 28b + budget - 28b = budget
    # So any b works as long as 28b < budget. With budget=370, b_max = 13.
    # Use b=10 as computed above.
    b = 10

    # Rounds: (num_active, keep)
    rounds = [(16, 8), (8, 4), (4, 2)]

    for n_active, keep in rounds:
        for idx in active:
            for _ in range(b):
                if used >= budget:
                    break
                r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                scores[idx] += (-1 if r else 1)
                used += 1
        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:keep]

    # Final duel with remaining budget
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)
            used += 1

    best = max(active, key=lambda i: scores[i])
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


# Also test accuracy per byte with correct intermediates
def test_per_byte_accuracy(budget=370, n_trials=500):
    """Test per-byte accuracy with correct intermediates (no cascade)."""
    import random
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
        best, _ = find_byte(ch, c2, true_inter, pos, c1[pos], budget)
        if best == true_inter[pos]:
            correct += 1
    return correct, n_trials


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'accuracy'

    if mode == 'accuracy':
        for budget in [125, 200, 250, 370]:
            c, n = test_per_byte_accuracy(budget, 500)
            print(f"Budget={budget}: per-byte accuracy={100*c/n:.1f}% → 32-byte: {(c/n)**32*100:.1f}%")

    elif mode == 'full':
        n_trials = int(sys.argv[2]) if len(sys.argv) > 2 else 200
        successes = 0
        wrongs = []
        for t in range(1, n_trials+1):
            ok, wrong, q = run_test()
            if ok: successes += 1
            wrongs.append(wrong)
            if t % 50 == 0 or t == n_trials:
                print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) avg_wrong={sum(wrongs)/len(wrongs):.1f} q_used≈{q}")
        print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
