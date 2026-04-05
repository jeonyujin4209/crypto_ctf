"""
Dual-CT padding oracle attack with cross-verification and backtracking.

Strategy:
- Get 2 free encryptions (CT1, CT2) with different IVs but same plaintext
- Attack each byte position using BOTH CTs independently
- Cross-verify: if plaintext bytes agree, high confidence; if not, resolve
- For byte positions where we disagree, try all combinations with more budget
- Budget: 12000 queries total, ~187 per byte-position, but we can be smarter
"""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
import sys
import time

rng_local = SystemRandom()
HEX_CHARS = [ord(c) for c in '0123456789abcdef']
LOG_RATIO = math.log(0.4 / 0.6)  # negative


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
    """Build a modified ciphertext for the padding oracle."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def score_candidate(true_count, total):
    """LLR score: positive means more likely valid padding."""
    if total == 0:
        return 0.0
    false_count = total - true_count
    return (false_count - true_count) * (-LOG_RATIO)


def find_byte_ranked(challenge, target, inter, pos, prev, budget):
    """
    Find byte at position pos. Returns list of (candidate, score) sorted by score descending.
    Uses sequential halving to efficiently narrow down.
    """
    pad = 16 - pos
    cands = [prev[pos] ^ h for h in HEX_CHARS]
    n_cands = len(cands)

    t_count = [0] * n_cands
    n_count = [0] * n_cands
    used = 0
    active = list(range(n_cands))

    # Phase 1: Quick screening (4 queries each for all 16)
    for idx in active:
        for _ in range(4):
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    # Eliminate bottom half
    scores = [score_candidate(t_count[i], n_count[i]) for i in range(n_cands)]
    active.sort(key=lambda i: scores[i], reverse=True)
    active = active[:8]

    # Phase 2: 8 more queries each for top 8
    for idx in active:
        for _ in range(8):
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    scores = [score_candidate(t_count[i], n_count[i]) for i in range(n_cands)]
    active.sort(key=lambda i: scores[i], reverse=True)
    active = active[:4]

    # Phase 3: 16 more each for top 4
    for idx in active:
        for _ in range(16):
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    scores = [score_candidate(t_count[i], n_count[i]) for i in range(n_cands)]
    active.sort(key=lambda i: scores[i], reverse=True)
    active = active[:2]

    # Phase 4: remaining budget on top 2
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    # Return all candidates with scores, sorted
    results = [(cands[i], score_candidate(t_count[i], n_count[i]), n_count[i]) for i in range(n_cands)]
    results.sort(key=lambda x: x[1], reverse=True)
    return results, used


def recover_block_dual(challenge, target1, prev1, target2, prev2, budget_per_byte):
    """
    Recover one plaintext block using two independent ciphertexts.
    For each byte position, attack with both CTs and cross-verify.
    """
    inter1 = [0] * 16
    inter2 = [0] * 16
    plaintext = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        # Budget allocation: split between two CTs
        # Give slightly more to first pass, save some for resolution
        budget_each = budget_per_byte // 2

        ranked1, u1 = find_byte_ranked(challenge, target1, inter1, pos, prev1, budget_each)
        ranked2, u2 = find_byte_ranked(challenge, target2, inter2, pos, prev2, budget_each)
        total_used += u1 + u2

        # Best candidates
        best1_cand = ranked1[0][0]
        best2_cand = ranked2[0][0]

        pt1 = best1_cand ^ prev1[pos]
        pt2 = best2_cand ^ prev2[pos]

        if pt1 == pt2:
            # Agreement - use it
            inter1[pos] = best1_cand
            inter2[pos] = best2_cand
            plaintext[pos] = pt1
        else:
            # Disagreement - try to resolve
            # Check top candidates from each CT for agreement
            resolved = False

            # Try top-3 from each
            for r1 in ranked1[:3]:
                for r2 in ranked2[:3]:
                    c1, s1, _ = r1
                    c2, s2, _ = r2
                    if (c1 ^ prev1[pos]) == (c2 ^ prev2[pos]):
                        # Found agreement
                        inter1[pos] = c1
                        inter2[pos] = c2
                        plaintext[pos] = c1 ^ prev1[pos]
                        resolved = True
                        break
                if resolved:
                    break

            if not resolved:
                # Take the one with higher score
                if ranked1[0][1] >= ranked2[0][1]:
                    inter1[pos] = best1_cand
                    inter2[pos] = best2_cand  # This will be wrong, but...
                    # Actually compute inter2 from the plaintext we believe
                    pt_byte = pt1
                    inter2[pos] = pt_byte ^ prev2[pos]  # Force consistency
                    plaintext[pos] = pt_byte
                else:
                    pt_byte = pt2
                    inter1[pos] = pt_byte ^ prev1[pos]
                    inter2[pos] = best2_cand
                    plaintext[pos] = pt_byte

    return inter1, inter2, plaintext, total_used


def run_test(budget_per_byte=375):
    ch = LocalChallenge()
    actual_msg = ch.message

    # Get two free encryptions
    ct_hex1 = ch.get_ct()
    ct_hex2 = ch.get_ct()

    ct1 = bytes.fromhex(ct_hex1)
    iv1 = list(ct1[:16])
    c1_1 = list(ct1[16:32])
    c1_2 = list(ct1[32:48])

    ct2 = bytes.fromhex(ct_hex2)
    iv2 = list(ct2[:16])
    c2_1 = list(ct2[16:32])
    c2_2 = list(ct2[32:48])

    ch.query_count = 0

    # Block 2 (bytes 16-31): target is c*_2, prev is c*_1
    _, _, pt2, q2 = recover_block_dual(ch, c1_2, c1_1, c2_2, c2_1, budget_per_byte)

    # Block 1 (bytes 0-15): target is c*_1, prev is iv*
    _, _, pt1, q1 = recover_block_dual(ch, c1_1, iv1, c2_1, iv2, budget_per_byte)

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
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    budget = int(sys.argv[2]) if len(sys.argv) > 2 else 375

    successes = 0
    wrong_counts = []
    total_start = time.time()

    for trial in range(1, n_trials + 1):
        result = run_test(budget)
        status = "OK" if result['correct'] else f"FAIL ({result['wrong_count']} wrong)"
        print(f"Trial {trial:3d}: {status}  q={result['queries']}")
        if result['correct']:
            successes += 1
        wrong_counts.append(result['wrong_count'])

    total_time = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"Results: {successes}/{n_trials} success ({100*successes/n_trials:.1f}%)")
    print(f"Wrong byte dist: {dict((k, wrong_counts.count(k)) for k in sorted(set(wrong_counts)))}")
    print(f"Avg wrong: {sum(wrong_counts)/len(wrong_counts):.1f}")
    print(f"Time: {total_time:.1f}s ({total_time/n_trials:.2f}s/trial)")
