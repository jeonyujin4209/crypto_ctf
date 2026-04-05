"""
Multi-CT majority vote approach.

Key idea: Get N free CTs. For each CT, run a cheap padding oracle attack on each byte.
Then for each plaintext byte position, take majority vote across all N CTs.

With N=5 CTs and ~150 queries/byte/CT, per-byte accuracy is maybe 90%.
Majority vote of 5 with 90% each: P(3+ correct) = ~99.1%
Over 32 bytes: 0.991^32 = 74.5%

With N=3 CTs and ~125 queries/byte/CT:
Total = 3 * 32 * 125 = 12000. Tight.
Per-byte ~88%. Majority of 3: P(2+ correct) = 3*0.88^2*0.12 + 0.88^3 = 96.1%
Over 32 bytes: 0.961^32 = 28%

Hmm, let's try N=5 with 75 queries/byte/CT:
Total = 5 * 32 * 75 = 12000.
Per-byte ~80%? Majority of 5: P(3+) = sum(C(5,k)*0.8^k*0.2^(5-k), k=3..5) = 94.2%
Over 32 bytes: 0.942^32 = 14.7%. Not great.

Actually N=3 with 125/byte seems optimal. Let me try.

Actually wait - each BLOCK needs its own cascade. Block has 16 bytes.
Error at pos15 cascades to 14..0 (15 more bytes).
Error at pos14 (given pos15 correct) cascades to 13..0 (14 bytes).
So effective per-byte accuracy is really per ORIGINAL byte accuracy (before cascade).

With majority vote across N independent CTs:
- Each CT independently runs the cascade
- The plaintext byte from CT_i for position j depends on ALL of inter[15], inter[14], ..., inter[j] being correct
- P(all bytes 15..j correct) = p^(16-j) where p is per-original-byte accuracy

For position 15: P_correct = p
For position 14: P_correct = p^2
...
For position 0: P_correct = p^16

Then majority vote on position j: P(majority correct) = MajVote(p^(16-j), N)

This is terrible for early positions if p < 1.

SO: the cascade is the fundamental problem. Majority vote helps but doesn't fix it.

BETTER APPROACH: Attack byte 15 across ALL CTs, take majority vote, then USE THE CONSENSUS
as the "known" intermediate for byte 14 in each CT. But wait, intermediate values differ per CT.

Hmm. Let me think again...

ACTUAL BEST APPROACH:
1. Get N CTs. For each CT, attack byte 15 independently using ~X queries.
2. Convert each CT's best candidate to plaintext: pt15_i = cand_i ^ prev_i[15]
3. Majority vote on pt15. Use this to SET inter[15] = consensus_pt ^ prev_i[15] for each CT.
4. Now attack byte 14 for each CT, using the CORRECTED inter[15].
5. Repeat.

This way, even if CT_i got byte 15 wrong, we correct it using the majority vote before
proceeding to byte 14. NO CASCADE!

Budget: N CTs × 16 bytes × Q queries = 12000
With N=3, Q = 12000/(3*16) = 250. Per-byte accuracy with 250 queries: ~93%.
Majority of 3 at 93%: P = 3*0.93^2*0.07 + 0.93^3 = 99.2%
Over 16 bytes per block × 2 blocks = 32: 0.992^32 = 77%!

With N=5, Q = 12000/(5*16) = 150. Per-byte accuracy: ~87%.
Majority of 5 at 87%: P(3+) = 96.7%
Over 32: 0.967^32 = 33%

N=3 with 250 seems better. Let me try N=4:
Q = 12000/(4*16) = ~187. Per-byte: ~90%.
Majority of 4 (need 3+): P = C(4,3)*0.9^3*0.1 + 0.9^4 = 4*0.729*0.1 + 0.6561 = 0.2916 + 0.6561 = 94.8%
Over 32: 0.948^32 = 18.2%

N=3 wins. Let's try it.

Actually, I realize per-byte accuracy estimates are rough. Let me just code it and test.
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
LOG_RATIO = math.log(0.4 / 0.6)


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


def score_candidate(true_count, total):
    if total == 0:
        return 0.0
    false_count = total - true_count
    return (false_count - true_count) * (-LOG_RATIO)


def find_byte_top(challenge, target, inter, pos, prev, budget):
    """Find best candidate for a byte. Returns (best_cand, score, all_ranked)."""
    pad = 16 - pos
    cands = [prev[pos] ^ h for h in HEX_CHARS]

    t_count = [0] * 16
    n_count = [0] * 16
    used = 0
    active = list(range(16))

    # Sequential halving: 16 -> 8 -> 4 -> 2 -> 1
    # Round 1: 4q each for 16 cands = 64
    phase_queries = [4, 8, 16]
    phase_keep = [8, 4, 2]

    for pq, pk in zip(phase_queries, phase_keep):
        for idx in active:
            for _ in range(pq):
                if used >= budget:
                    break
                result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                t_count[idx] += int(result)
                n_count[idx] += 1
                used += 1
        scores = [score_candidate(t_count[i], n_count[i]) for i in range(16)]
        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:pk]

    # Remaining budget on top 2
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    scores = [score_candidate(t_count[i], n_count[i]) for i in range(16)]
    best = max(active, key=lambda i: scores[i])

    ranked = sorted(range(16), key=lambda i: scores[i], reverse=True)
    return cands[best], scores[best], [(cands[i], scores[i]) for i in ranked], used


def recover_block_multi_ct(challenge, ct_data_list, budget_per_byte_per_ct):
    """
    Recover plaintext block using multiple CTs with consensus correction.

    ct_data_list: list of (target_block, prev_block) tuples
    """
    N = len(ct_data_list)

    # Intermediate values for each CT
    inters = [[0]*16 for _ in range(N)]
    plaintext = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        # Attack this byte with each CT independently
        pt_votes = {}  # pt_byte -> [(ct_idx, cand, score)]
        all_results = []

        for ci in range(N):
            target, prev = ct_data_list[ci]
            cand, score, ranked, used = find_byte_top(
                challenge, target, inters[ci], pos, prev, budget_per_byte_per_ct
            )
            total_used += used
            pt_byte = cand ^ prev[pos]
            all_results.append((ci, cand, score, ranked, prev[pos]))

            if pt_byte not in pt_votes:
                pt_votes[pt_byte] = []
            pt_votes[pt_byte].append((ci, cand, score))

        # Find consensus: the plaintext byte with most votes (weighted by score)
        best_pt = None
        best_weight = -float('inf')

        for pt_byte, votes in pt_votes.items():
            # Check it's a valid hex char
            if pt_byte not in HEX_CHARS:
                continue
            weight = sum(s for _, _, s in votes)
            if len(votes) > best_weight or (len(votes) == best_weight and weight > best_weight):
                best_pt = pt_byte
                best_weight = len(votes)

        # If no hex char got votes (shouldn't happen), pick highest score overall
        if best_pt is None:
            # Fallback: just use the highest-scoring result
            best_ci, best_cand, best_score, _, best_prev = max(all_results, key=lambda x: x[2])
            best_pt = best_cand ^ best_prev

        # Now try harder: consider top candidates from each CT for hex-char agreement
        # Collect all possible pt bytes that are hex chars
        hex_scores = {}  # pt_byte -> total_score
        for ci, cand, score, ranked, prev_byte in all_results:
            for c, s in ranked[:4]:  # top 4 from each CT
                pt = c ^ prev_byte
                if pt in HEX_CHARS:
                    if pt not in hex_scores:
                        hex_scores[pt] = 0
                    hex_scores[pt] += s

        if hex_scores:
            best_pt = max(hex_scores, key=hex_scores.get)

        plaintext[pos] = best_pt

        # Set intermediates for ALL CTs based on consensus plaintext
        for ci in range(N):
            _, prev = ct_data_list[ci]
            inters[ci][pos] = best_pt ^ prev[pos]

    return plaintext, total_used


def run_test(n_cts=3, total_budget=12000):
    ch = LocalChallenge()
    actual_msg = ch.message

    # Get multiple free CTs
    cts = []
    for _ in range(n_cts):
        ct_hex = ch.get_ct()
        ct_bytes = bytes.fromhex(ct_hex)
        iv = list(ct_bytes[:16])
        c1 = list(ct_bytes[16:32])
        c2 = list(ct_bytes[32:48])
        cts.append((iv, c1, c2))

    ch.query_count = 0
    budget_per_byte_per_ct = total_budget // (n_cts * 32)

    # Block 2: target=c2, prev=c1
    block2_data = [(ct[2], ct[1]) for ct in cts]
    pt2, q2 = recover_block_multi_ct(ch, block2_data, budget_per_byte_per_ct)

    # Block 1: target=c1, prev=iv
    block1_data = [(ct[1], ct[0]) for ct in cts]
    pt1, q1 = recover_block_multi_ct(ch, block1_data, budget_per_byte_per_ct)

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
    n_cts = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    successes = 0
    wrong_counts = []

    for trial in range(1, n_trials + 1):
        result = run_test(n_cts=n_cts)
        status = "OK" if result['correct'] else f"FAIL ({result['wrong_count']} wrong)"
        print(f"Trial {trial:3d}: {status}  q={result['queries']}")
        if result['correct']:
            successes += 1
        wrong_counts.append(result['wrong_count'])

    print(f"\n{'='*60}")
    print(f"N_CTs={n_cts}")
    print(f"Results: {successes}/{n_trials} success ({100*successes/n_trials:.1f}%)")
    print(f"Wrong byte dist: {dict((k, wrong_counts.count(k)) for k in sorted(set(wrong_counts)))}")
    print(f"Avg wrong: {sum(wrong_counts)/len(wrong_counts):.1f}")
