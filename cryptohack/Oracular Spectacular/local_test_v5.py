"""
Strategy: Single CT with hex-char verification and retry.

1. Attack both blocks with 350 queries/byte = 11200 total
2. Check hex constraint:
   - If both blocks have all hex chars → submit
   - If a block has non-hex chars → attempt to fix

3. If a block needs fixing:
   - Get a new CT for retry
   - Find the cascade start point:
     * Bytes closer to pos=15 are more likely correct
     * First non-hex byte (from pos=15 downward) indicates cascade started nearby
   - Re-attack from the cascade start with remaining budget using new CT

4. Remaining budget: 12000 - 11200 = 800 queries
   - If one block fails: retry that block with 800 queries = 50/byte for 16 bytes
     This is very low. Better: retry only the few bytes at cascade start.

Actually better approach:
- Budget: 350/byte * 32 = 11200
- After hex check, if BOTH blocks pass (P ≈ 7.8%² = 0.6%), submit
- If one block fails, we have 800 queries. Not enough for full retry.
- Strategy: if block fails, assume cascade started at first error byte.
  Try 3-4 alternative candidates for that byte, spending 200 queries each to verify.
  800/200 = 4 verification attempts.

For verification: test one specific candidate with 200 queries.
If True rate ≈ 0.4 → it's correct. If ≈ 0.6 → it's wrong.
With 200 queries: P(correct classification) ≈ Φ(0.2*200/sqrt(200*0.96)) = Φ(2.89) = 99.8%.

So: try each alternative candidate, check if it gives valid padding → find the correct byte.
Then recompute bytes below it.
But recomputing bytes below needs more queries...

Hmm, this is getting complicated. Let me just test the basic approach first.
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


def make_ct(target_block, inter, pos, pad, cand):
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
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    # Also return second best and all llr
    sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
    return cands[best], [cands[i] for i in sorted_idx], llr, used


def recover_block_with_alts(oracle_fn, target_block, prev_block, budget_per_byte):
    """Recover block, keeping track of alternatives."""
    inter = [0] * 16
    alternatives = [[] for _ in range(16)]  # alternatives[pos] = list of (cand, llr)
    total_used = 0

    for pos in range(15, -1, -1):
        best, sorted_cands, llr, used = find_byte(
            oracle_fn, target_block, inter, pos, prev_block[pos], budget_per_byte
        )
        inter[pos] = best
        # Store top 3 alternatives
        cands_with_llr = [(c, llr[i]) for i, c in enumerate([prev_block[pos] ^ h for h in HEX_LIST])]
        cands_with_llr.sort(key=lambda x: x[1], reverse=True)
        alternatives[pos] = cands_with_llr[:4]
        total_used += used

    plaintext = bytes([inter[i] ^ prev_block[i] for i in range(16)])
    return inter, plaintext, alternatives, total_used


def solve(challenge, max_budget=12000):
    """Main solve with hex verification and retry logic."""
    ct_hex = challenge.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    budget_per_byte = 350
    used_total = 0

    # Recover block 2
    i2, pt2, alts2, q2 = recover_block_with_alts(
        challenge.check_padding, c2, c1, budget_per_byte
    )
    used_total += q2

    # Recover block 1
    i1, pt1, alts1, q1 = recover_block_with_alts(
        challenge.check_padding, c1, iv, budget_per_byte
    )
    used_total += q1

    recovered = (pt1 + pt2).decode('ascii', 'replace')

    # Check hex constraint
    is_hex = all(c in '0123456789abcdef' for c in recovered)
    if is_hex:
        return recovered, used_total

    # If not all hex, try to fix using remaining budget
    remaining = max_budget - used_total

    # Check which blocks need fixing
    block1_hex = all(c in '0123456789abcdef' for c in recovered[:16])
    block2_hex = all(c in '0123456789abcdef' for c in recovered[16:])

    # For each bad block: try alternative candidates at each position (starting from 15)
    # Use a new CT for verification
    for block_idx, (inter, pt, alts, target, prev) in enumerate([
        (i1, pt1, alts1, c1, iv),
        (i2, pt2, alts2, c2, c1)
    ]):
        pt_str = pt.decode('ascii', 'replace')
        block_ok = all(c in '0123456789abcdef' for c in pt_str)
        if block_ok:
            continue

        # Find first wrong byte (from pos 15 down)
        first_bad = None
        for pos in range(15, -1, -1):
            if pt_str[pos] not in '0123456789abcdef':
                first_bad = pos
                break

        if first_bad is None:
            continue  # All hex but some might be wrong

        # The cascade likely started at first_bad or above.
        # Try to fix bytes from first_bad upward.
        # Actually, the first non-hex byte is at position first_bad (counting from pos=0).
        # But bytes are recovered from pos=15 down, so cascade flows downward.
        # If byte at pos=K (closer to 15) was wrong, all bytes K-1, K-2, ..., 0 are wrong.
        # So the first non-hex byte counting from pos=15 downward tells us cascade start.

        first_bad_from_top = None
        for pos in range(15, -1, -1):
            if pt_str[pos] not in '0123456789abcdef':
                first_bad_from_top = pos
                break

        # Actually: bytes 15, 14, ..., first_bad_from_top+1 are all hex → probably correct
        # Byte first_bad_from_top is non-hex → cascade started at or above this byte
        # But the cascade start byte itself MIGHT be hex (wrong hex char)!

        # Best we can do: the cascade started at some byte between first_bad_from_top and 15.
        # Try alternative candidates for bytes just above first_bad_from_top.

        # With limited budget, try: test the top alternative for each byte from
        # first_bad_from_top up to first_bad_from_top+2 (3 positions)
        cascade_start_candidates = range(min(15, first_bad_from_top + 3),
                                          max(-1, first_bad_from_top - 1), -1)

        # Get a new CT for verification
        ct2_hex = challenge.get_ct()
        ct2_b = bytes.fromhex(ct2_hex)
        if block_idx == 0:
            target2 = list(ct2_b[16:32])
            prev2 = list(ct2_b[:16])
        else:
            target2 = list(ct2_b[32:48])
            prev2 = list(ct2_b[16:32])

        for pos in cascade_start_candidates:
            if remaining < 50:
                break

            # Verify current byte with new CT
            pad = 16 - pos
            # Build correct intermediates for the new CT using our current plaintext guess
            inter2 = [0] * 16
            for k in range(15, pos, -1):
                inter2[k] = (inter[k] ^ prev[k]) ^ prev2[k]  # pt_byte ^ prev2

            # Test current candidate
            current_cand = inter[pos]
            current_inter2_byte = (current_cand ^ prev[pos]) ^ prev2[pos]  # pt_byte for new CT

            n_true = 0
            n_q = min(30, remaining)
            for _ in range(n_q):
                m = bytearray(os.urandom(16))
                for k in range(pos + 1, 16):
                    m[k] = inter2[k] ^ pad
                m[pos] = current_inter2_byte ^ pad
                r = challenge.check_padding((bytes(m) + bytes(target2)).hex())
                n_true += int(r)
                remaining -= 1

            # If True rate is ~0.4, current is correct. If ~0.6, it's wrong.
            if n_true / n_q < 0.5:  # Looks correct
                continue

            # Current byte seems wrong. Try alternatives.
            for alt_cand, _ in alts[pos][1:4]:  # top alternatives after the best
                if remaining < 30:
                    break

                alt_pt = alt_cand ^ prev[pos]
                if alt_pt not in HEX_SET:
                    continue

                alt_inter2_byte = alt_pt ^ prev2[pos]
                n_true = 0
                n_q = min(30, remaining)
                for _ in range(n_q):
                    m = bytearray(os.urandom(16))
                    for k in range(pos + 1, 16):
                        m[k] = inter2[k] ^ pad
                    m[pos] = alt_inter2_byte ^ pad
                    r = challenge.check_padding((bytes(m) + bytes(target2)).hex())
                    n_true += int(r)
                    remaining -= 1

                if n_true / n_q < 0.5:  # This alternative seems correct
                    inter[pos] = alt_cand
                    # Re-attack bytes below pos with the corrected intermediate
                    # ... but we don't have enough budget for that
                    break

    # Recompute plaintext
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])
    recovered = (pt1 + pt2).decode('ascii', 'replace')

    return recovered, max_budget - remaining


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 2000

    successes = 0
    wrongs = []
    hex_pass = 0
    total_start = time.time()

    for t in range(1, n_trials + 1):
        ch = LocalChallenge()
        recovered, q_used = solve(ch)
        ok = recovered == ch.message
        wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])
        all_hex = all(c in '0123456789abcdef' for c in recovered)

        if ok:
            successes += 1
        if all_hex:
            hex_pass += 1
        wrongs.append(wrong)

        if t % 500 == 0 or t == n_trials:
            elapsed = time.time() - total_start
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) "
                  f"hex_pass={hex_pass}/{t} ({100*hex_pass/t:.1f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f}")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
