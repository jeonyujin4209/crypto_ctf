"""
Dual-CT byte-by-byte consensus with adaptive budget.

For each byte position (15 down to 0):
1. Attack with CT1 using adaptive top-2 (budget B1)
2. Attack with CT2 using adaptive top-2 (budget B2)
3. If plaintext bytes agree → accept, advance
4. If disagree → spend more queries on both until budget exhausted or agreement
5. Use consensus to set intermediates for next byte

Key: intermediates for byte k-1 depend only on bytes k..15,
which have been consensus-verified. No cascade!
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


def make_ct_for_byte(target_block, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target_block)).hex()


def attack_byte(oracle_fn, target_block, inter, pos, prev_byte, budget):
    """Adaptive top-2. Returns (best_cand, llr_dict, used)."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    # Screen
    for idx in range(16):
        for _ in range(2):
            if used >= budget:
                break
            r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive top-2
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], {i: llr[i] for i in range(16)}, used


def add_queries(oracle_fn, target_block, inter, pos, prev_byte, llr_dict, cand_idx, n_queries):
    """Add more queries to a specific candidate."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    used = 0

    for _ in range(n_queries):
        r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, cands[cand_idx]))
        llr_dict[cand_idx] += LOG_P if r else -LOG_P
        used += 1

    return used


def solve(challenge, max_budget=12000):
    """Main solve with dual-CT consensus."""
    # Get 2 CTs
    ct1_hex = challenge.get_ct()
    ct2_hex = challenge.get_ct()

    ct1 = bytes.fromhex(ct1_hex)
    iv1, c1_1, c1_2 = list(ct1[:16]), list(ct1[16:32]), list(ct1[32:48])

    ct2 = bytes.fromhex(ct2_hex)
    iv2, c2_1, c2_2 = list(ct2[:16]), list(ct2[16:32]), list(ct2[32:48])

    used = [0]

    def oracle(ct_hex):
        used[0] += 1
        return challenge.check_padding(ct_hex)

    plaintext = [0] * 32

    # Process each block
    for block_idx, (target1, prev1, target2, prev2) in enumerate([
        (c1_2, c1_1, c2_2, c2_1),  # Block 2 (bytes 16-31)
        (c1_1, iv1, c2_1, iv2),     # Block 1 (bytes 0-15)
    ]):
        inter1 = [0] * 16
        inter2 = [0] * 16

        byte_offset = 16 if block_idx == 0 else 0

        # Budget per byte for this block: aim for total per block ≤ 6000
        base_budget_per_ct = 150  # 150 per CT per byte initially

        for pos in range(15, -1, -1):
            remaining = max_budget - used[0]
            bytes_left = pos + 1 + (16 if block_idx == 0 else 0)
            budget_for_this_byte = min(remaining // max(1, bytes_left // 2 + 1), 600)
            budget_per_ct = budget_for_this_byte // 2

            if budget_per_ct < 32:  # Not enough for even screening
                budget_per_ct = 32

            # Attack with CT1
            best1, llr1, u1 = attack_byte(oracle, target1, inter1, pos, prev1[pos], budget_per_ct)
            pt1 = best1 ^ prev1[pos]

            # Attack with CT2
            best2, llr2, u2 = attack_byte(oracle, target2, inter2, pos, prev2[pos], budget_per_ct)
            pt2 = best2 ^ prev2[pos]

            if pt1 == pt2:
                # Agreement! Accept.
                consensus = pt1
            else:
                # Disagreement. Use more budget to resolve.
                # Find the hex char that each CT ranks highest
                cands1 = [prev1[pos] ^ h for h in HEX_LIST]
                cands2 = [prev2[pos] ^ h for h in HEX_LIST]

                # Try to find agreement: check if CT1's top matches any of CT2's top 3
                sorted1 = sorted(range(16), key=lambda i: llr1[i], reverse=True)
                sorted2 = sorted(range(16), key=lambda i: llr2[i], reverse=True)

                pt1_top3 = [cands1[i] ^ prev1[pos] for i in sorted1[:3]]
                pt2_top3 = [cands2[i] ^ prev2[pos] for i in sorted2[:3]]

                # Find common answers
                common = set(pt1_top3) & set(pt2_top3)
                if common:
                    # Use the common answer that has highest combined LLR
                    best_common = None
                    best_score = -float('inf')
                    for pt in common:
                        idx1 = HEX_LIST.index(pt) if pt in HEX_LIST else -1
                        if idx1 < 0:
                            continue
                        # Find this pt's index in each CT's candidate list
                        cidx1 = cands1.index(pt ^ prev1[pos]) if (pt ^ prev1[pos]) in cands1 else -1
                        cidx2 = cands2.index(pt ^ prev2[pos]) if (pt ^ prev2[pos]) in cands2 else -1
                        if cidx1 >= 0 and cidx2 >= 0:
                            score = llr1.get(cidx1, 0) + llr2.get(cidx2, 0)
                            if score > best_score:
                                best_score = score
                                best_common = pt
                    if best_common is not None:
                        consensus = best_common
                    else:
                        # No good common → use CT with higher score
                        if llr1[sorted1[0]] >= llr2[sorted2[0]]:
                            consensus = pt1
                        else:
                            consensus = pt2
                else:
                    # No common in top 3 → use CT with higher score
                    if llr1[sorted1[0]] >= llr2[sorted2[0]]:
                        consensus = pt1
                    else:
                        consensus = pt2

            plaintext[byte_offset + pos] = consensus
            inter1[pos] = consensus ^ prev1[pos]
            inter2[pos] = consensus ^ prev2[pos]

    recovered = bytes(plaintext).decode('ascii', 'replace')
    return recovered, used[0]


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 2000

    successes = 0
    wrongs = []
    total_start = time.time()

    for t in range(1, n_trials + 1):
        ch = LocalChallenge()
        recovered, q_used = solve(ch)
        ok = recovered == ch.message
        wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])

        if ok:
            successes += 1
        wrongs.append(wrong)

        if t % 500 == 0 or t == n_trials:
            elapsed = time.time() - total_start
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f} "
                  f"q~{q_used} time={elapsed:.0f}s")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    for k in sorted(dist):
        if dist[k] >= 5:
            print(f"  {k} wrong: {dist[k]} ({100*dist[k]/n_trials:.1f}%)")
