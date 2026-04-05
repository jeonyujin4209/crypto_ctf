"""
Final solver: 3 CTs with adaptive top-2 and consensus at each step.
Expected per-byte accuracy: ~89%
Expected per-32-byte success: ~2.7%
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
LOG_P = math.log(0.4 / 0.6)  # ≈ -0.405


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
    """Build modified ciphertext for padding oracle query."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def find_byte_adaptive(challenge, target, inter, pos, prev_byte, budget):
    """
    Adaptive top-2: screen all 16 candidates with 2 queries each,
    then focus remaining budget on top 2 candidates.
    Returns (best_candidate, llr_scores_dict).
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    counts = [0] * 16
    used = 0

    # Screen: 2 queries per candidate = 32 queries
    screen_q = 2
    for idx in range(16):
        for _ in range(screen_q):
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            counts[idx] += 1
            used += 1

    # Adaptive: focus on top 2 by LLR
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for target_idx in sorted_idx[:2]:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[target_idx]))
            llr[target_idx] += LOG_P if r else -LOG_P
            counts[target_idx] += 1
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], {cands[i]: llr[i] for i in range(16)}, used


def recover_block_consensus(challenge, ct_data_list, budget_per_byte_per_ct):
    """
    Recover one plaintext block using N CTs with consensus at each step.
    ct_data_list: [(target_block, prev_block), ...]
    """
    N = len(ct_data_list)
    inters = [[0]*16 for _ in range(N)]
    plaintext = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        # Attack with each CT
        votes = Counter()
        ct_results = []

        for ci in range(N):
            target, prev = ct_data_list[ci]
            best_cand, llr_dict, used = find_byte_adaptive(
                challenge, target, inters[ci], pos, prev[pos], budget_per_byte_per_ct
            )
            total_used += used

            pt_byte = best_cand ^ prev[pos]
            ct_results.append((ci, best_cand, pt_byte, llr_dict, prev[pos]))
            votes[pt_byte] += 1

        # Find consensus: majority vote among hex chars
        consensus_pt = None
        for pt_byte, count in votes.most_common():
            if pt_byte in HEX_SET:
                consensus_pt = pt_byte
                break

        if consensus_pt is None:
            # Fallback: just use the first CT's result
            consensus_pt = ct_results[0][2]

        plaintext[pos] = consensus_pt

        # Set intermediates for ALL CTs based on consensus
        for ci in range(N):
            _, _, _, _, prev_byte = ct_results[ci]
            inters[ci][pos] = consensus_pt ^ prev_byte

    return plaintext, total_used


def run_test(n_cts=3, total_budget=12000):
    ch = LocalChallenge()
    actual_msg = ch.message

    # Get N free CTs
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

    # Block 2: target=c2, prev=c1
    block2_data = [(ct[2], ct[1]) for ct in cts]
    pt2, q2 = recover_block_consensus(ch, block2_data, budget_per_byte_per_ct)

    # Block 1: target=c1, prev=iv
    block1_data = [(ct[1], ct[0]) for ct in cts]
    pt1, q1 = recover_block_consensus(ch, block1_data, budget_per_byte_per_ct)

    recovered = bytes(pt1 + pt2).decode('ascii', 'replace')
    total_q = ch.query_count

    wrong_bytes = [i for i in range(32) if recovered[i] != actual_msg[i]]

    return {
        'actual': actual_msg,
        'recovered': recovered,
        'correct': recovered == actual_msg,
        'wrong_count': len(wrong_bytes),
        'wrong_positions': wrong_bytes,
        'queries': total_q,
    }


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    n_cts = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    successes = 0
    wrongs = []
    total_start = time.time()

    for trial in range(1, n_trials + 1):
        result = run_test(n_cts=n_cts)
        if result['correct']:
            successes += 1
        wrongs.append(result['wrong_count'])

        if trial % 50 == 0 or trial == n_trials:
            print(f"After {trial}: {successes}/{trial} ({100*successes/trial:.1f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f} q={result['queries']}")

    total_time = time.time() - total_start
    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    print(f"Wrong dist: {dict(sorted(dist.items()))}")
    print(f"Time: {total_time:.1f}s ({total_time/n_trials:.2f}s/trial)")
