"""
Strategy: Single CT attack + 2nd CT verification of critical bytes.

1. Get CT1 for attack, CT2 for verification
2. Attack all 32 bytes with CT1 at 340/byte = 10880
3. For each block, verify bytes 15-10 with CT2:
   - For each byte, test the found candidate using CT2
   - 40 queries each → 6 × 2 × 40 = 480 verification queries
4. If a byte fails verification (more True than False → probably wrong):
   - Re-attack with CT2, 100 queries for that byte
5. Total: 10880 + 480 + some re-attacks ≈ 11600

Key: byte 15's verification uses NO intermediates (pad=1, only byte 15 matters).
Byte 14's verification uses byte 15's intermediate (which we just verified).
So cascade in verification is also broken!
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


def make_ct_raw(target_block, modified_block):
    """Build ciphertext from modified IV/prev block and target."""
    return (bytes(modified_block) + bytes(target_block)).hex()


def make_ct_for_byte(target_block, inter, pos, pad, cand):
    """Build modified ciphertext for padding oracle query at position pos."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target_block)).hex()


def find_byte(oracle_fn, target_block, inter, pos, prev_byte, budget):
    """Adaptive top-2."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    for idx in range(16):
        for _ in range(2):
            if used >= budget:
                break
            r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], llr, used


def verify_byte(oracle_fn, target_block, inter, pos, candidate, n_queries):
    """Verify a specific candidate using oracle queries. Returns (is_valid, n_true, n_total)."""
    pad = 16 - pos
    n_true = 0
    for _ in range(n_queries):
        r = oracle_fn(make_ct_for_byte(target_block, inter, pos, pad, candidate))
        n_true += int(r)
    return n_true / n_queries < 0.5, n_true, n_queries


def solve(challenge, max_budget=12000):
    """Main solve with verification."""
    # Get CTs
    ct1_hex = challenge.get_ct()  # For attack
    ct2_hex = challenge.get_ct()  # For verification

    ct1 = bytes.fromhex(ct1_hex)
    iv1 = list(ct1[:16])
    c1_1 = list(ct1[16:32])
    c1_2 = list(ct1[32:48])

    ct2 = bytes.fromhex(ct2_hex)
    iv2 = list(ct2[:16])
    c2_1 = list(ct2[16:32])
    c2_2 = list(ct2[32:48])

    # Budget planning
    attack_budget_per_byte = 340
    verify_queries = 40
    reattack_budget = 100
    n_verify_bytes = 8  # verify bytes 15-8 for each block

    used = [0]  # mutable counter

    def oracle_counted(ct_hex):
        used[0] += 1
        return challenge.check_padding(ct_hex)

    # Attack both blocks with CT1
    # Block 2 (target=c1_2, prev=c1_1)
    inter2 = [0] * 16
    for pos in range(15, -1, -1):
        best, llr, q = find_byte(oracle_counted, c1_2, inter2, pos, c1_1[pos], attack_budget_per_byte)
        inter2[pos] = best

    # Block 1 (target=c1_1, prev=iv1)
    inter1 = [0] * 16
    for pos in range(15, -1, -1):
        best, llr, q = find_byte(oracle_counted, c1_1, inter1, pos, iv1[pos], attack_budget_per_byte)
        inter1[pos] = best

    # Compute plaintext from CT1
    pt1 = [inter1[i] ^ iv1[i] for i in range(16)]
    pt2 = [inter2[i] ^ c1_1[i] for i in range(16)]

    # Verification with CT2
    # For block 2: CT2's target=c2_2, prev=c2_1
    # The plaintext should be the same. So CT2's intermediate at pos should be pt[pos] ^ c2_prev[pos]
    # Verify: set up padding using CT2's intermediates, check if candidate gives valid padding

    # Build CT2's expected intermediates based on our plaintext guess
    inter2_ct2 = [pt2[i] ^ c2_1[i] for i in range(16)]

    # Verify bytes 15 down to (16 - n_verify_bytes) for block 2
    for pos in range(15, 15 - n_verify_bytes, -1):
        if used[0] >= max_budget - 50:
            break

        is_valid, n_true, n_total = verify_byte(
            oracle_counted, c2_2, inter2_ct2, pos, inter2_ct2[pos], verify_queries
        )

        if not is_valid:
            # Byte pos is probably wrong. Re-attack with CT2.
            if used[0] + reattack_budget > max_budget:
                break

            # Re-attack this byte with CT2
            best, llr, q = find_byte(
                oracle_counted, c2_2, inter2_ct2, pos, c2_1[pos], reattack_budget
            )

            # Update plaintext and intermediates
            new_pt = best ^ c2_1[pos]
            pt2[pos] = new_pt
            inter2[pos] = new_pt ^ c1_1[pos]
            inter2_ct2[pos] = new_pt ^ c2_1[pos]

            # Also update intermediates below this position for both CTs
            # (they depend on inter at this position)
            # Actually, the intermediates below are independently found.
            # The issue is that bytes below pos in CT1 were found using potentially wrong
            # inter[pos], so they might be wrong too. But re-attacking them requires budget.

    # Similarly for block 1 with CT2
    inter1_ct2 = [pt1[i] ^ iv2[i] for i in range(16)]

    for pos in range(15, 15 - n_verify_bytes, -1):
        if used[0] >= max_budget - 50:
            break

        is_valid, n_true, n_total = verify_byte(
            oracle_counted, c2_1, inter1_ct2, pos, inter1_ct2[pos], verify_queries
        )

        if not is_valid:
            if used[0] + reattack_budget > max_budget:
                break

            best, llr, q = find_byte(
                oracle_counted, c2_1, inter1_ct2, pos, iv2[pos], reattack_budget
            )

            new_pt = best ^ iv2[pos]
            pt1[pos] = new_pt
            inter1[pos] = new_pt ^ iv1[pos]
            inter1_ct2[pos] = new_pt ^ iv2[pos]

    recovered = bytes(pt1 + pt2).decode('ascii', 'replace')
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
                  f"time={elapsed:.0f}s")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    for k in sorted(dist):
        if dist[k] >= 5:
            print(f"  {k} wrong: {dist[k]} ({100*dist[k]/n_trials:.1f}%)")
