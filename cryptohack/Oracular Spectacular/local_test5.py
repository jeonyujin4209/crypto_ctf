"""
Clean implementation. Focus on getting per-byte accuracy right first.

Key insight for scoring:
- Valid padding → P(True) = 0.4, P(False) = 0.6
- Invalid padding → P(True) = 0.6, P(False) = 0.4
- So for valid candidate: expect MORE False responses
- Score = (false_count - true_count) should be POSITIVE for valid, NEGATIVE for invalid
- With n queries on valid: E[score] = n*(0.6-0.4) = 0.2n
- With n queries on invalid: E[score] = n*(0.4-0.6) = -0.2n
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
    """
    Find intermediate byte at position pos using sequential halving.
    Score = false_count - true_count (higher = more likely valid).
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]

    scores = [0] * 16  # false - true counts
    n_queries = [0] * 16
    used = 0
    active = list(range(16))

    # Sequential halving: 16 → 8 → 4 → 2, then final duel
    rounds = [(5, 8), (10, 4), (20, 2)]

    for q_each, keep in rounds:
        for idx in active:
            for _ in range(q_each):
                if used >= budget:
                    break
                r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                if r:
                    scores[idx] -= 1  # True → decrease score
                else:
                    scores[idx] += 1  # False → increase score
                n_queries[idx] += 1
                used += 1
        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:keep]

    # Final duel with remaining budget
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            if r:
                scores[idx] -= 1
            else:
                scores[idx] += 1
            n_queries[idx] += 1
            used += 1

    best = max(active, key=lambda i: scores[i])

    # Return best and runner-up
    active.sort(key=lambda i: scores[i], reverse=True)
    return cands[best], cands[active[1]] if len(active) > 1 else cands[best], used


def recover_block(challenge, target, prev, budget_per_byte):
    """Recover one block, returning intermediates."""
    inter = [0] * 16
    total_used = 0
    for pos in range(15, -1, -1):
        best, runner_up, used = find_byte(challenge, target, inter, pos, prev[pos], budget_per_byte)
        inter[pos] = best
        total_used += used
    return inter, total_used


def recover_block_multi_ct(challenge, ct_data_list, budget_per_byte_per_ct):
    """
    Recover plaintext block using N CTs with consensus at each step.
    ct_data_list: [(target, prev), ...]
    """
    N = len(ct_data_list)
    inters = [[0]*16 for _ in range(N)]
    plaintext = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        votes = Counter()
        ct_results = []

        for ci in range(N):
            target, prev = ct_data_list[ci]
            best, runner_up, used = find_byte(
                challenge, target, inters[ci], pos, prev[pos], budget_per_byte_per_ct
            )
            total_used += used

            pt_byte = best ^ prev[pos]
            pt_runner = runner_up ^ prev[pos]
            ct_results.append((ci, best, runner_up, prev[pos]))

            # Only count hex char votes
            if pt_byte in HEX_LIST:
                votes[pt_byte] += 1

        # Consensus
        if votes:
            consensus_pt = votes.most_common(1)[0][0]
        else:
            # Fallback: use first CT's best
            consensus_pt = ct_results[0][1] ^ ct_results[0][3]

        plaintext[pos] = consensus_pt

        # Set all intermediates consistently
        for ci in range(N):
            _, _, _, prev_byte = ct_results[ci]
            inters[ci][pos] = consensus_pt ^ prev_byte

    return plaintext, total_used


def run_test_single(budget_per_byte=370):
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


def run_test_multi(n_cts=3, total_budget=12000):
    ch = LocalChallenge()
    actual_msg = ch.message

    cts = []
    for _ in range(n_cts):
        ct_hex = ch.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        iv = list(ct_b[:16])
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cts.append((iv, c1, c2))

    ch.query_count = 0
    budget_per_byte_per_ct = total_budget // (n_cts * 32)

    block2_data = [(ct[2], ct[1]) for ct in cts]
    pt2, q2 = recover_block_multi_ct(ch, block2_data, budget_per_byte_per_ct)

    block1_data = [(ct[1], ct[0]) for ct in cts]
    pt1, q1 = recover_block_multi_ct(ch, block1_data, budget_per_byte_per_ct)

    recovered = bytes(pt1 + pt2).decode('ascii', 'replace')
    wrong = sum(1 for i in range(32) if recovered[i] != actual_msg[i])
    return recovered == actual_msg, wrong, ch.query_count


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'single'
    n_trials = int(sys.argv[2]) if len(sys.argv) > 2 else 50

    successes = 0
    wrongs = []

    for t in range(1, n_trials + 1):
        if mode == 'single':
            ok, wrong, q = run_test_single(370)
        elif mode == 'multi':
            n_cts = int(sys.argv[3]) if len(sys.argv) > 3 else 3
            ok, wrong, q = run_test_multi(n_cts)
        else:
            break

        if ok:
            successes += 1
        wrongs.append(wrong)
        if t % 10 == 0 or t == n_trials:
            print(f"After {t} trials: {successes}/{t} ({100*successes/t:.1f}%) avg_wrong={sum(wrongs)/len(wrongs):.1f}")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    print(f"Wrong dist: {dict(sorted(dist.items()))}")
