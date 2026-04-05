"""
Debug: First test single CT with generous budget to understand per-byte accuracy.
Then test multi-CT consensus.
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
HEX_CHARS = set(ord(c) for c in '0123456789abcdef')
HEX_LIST = [ord(c) for c in '0123456789abcdef']
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


def make_ct_bytes(target, inter, pos, pad, cand):
    """Build modified ciphertext. Returns bytes."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def find_byte_single(challenge, target, inter, pos, prev_byte, budget):
    """
    Find the intermediate byte at position pos.
    Returns (best_cand, confidence_gap, top2_cands).
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]

    true_counts = [0] * 16
    total_counts = [0] * 16
    used = 0
    active = list(range(16))

    # Sequential halving
    rounds = [(5, 8), (10, 4), (20, 2)]

    for q_each, keep in rounds:
        for idx in active:
            for _ in range(q_each):
                if used >= budget:
                    break
                r = challenge.check_padding(make_ct_bytes(target, inter, pos, pad, cands[idx]))
                true_counts[idx] += int(r)
                total_counts[idx] += 1
                used += 1

        # Score: higher = more likely valid (more False responses = valid at 60% rate)
        def score(i):
            if total_counts[i] == 0:
                return 0
            return (total_counts[i] - true_counts[i] - true_counts[i])  # false - true

        active.sort(key=score, reverse=True)
        active = active[:keep]

    # Final duel
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct_bytes(target, inter, pos, pad, cands[idx]))
            true_counts[idx] += int(r)
            total_counts[idx] += 1
            used += 1

    def score(i):
        if total_counts[i] == 0:
            return 0
        return total_counts[i] - 2 * true_counts[i]  # false - true

    best = max(active, key=score)
    scores_active = [(i, score(i)) for i in active]
    scores_active.sort(key=lambda x: x[1], reverse=True)

    return cands[best], scores_active, used


def test_single_ct_no_cascade():
    """Test per-byte accuracy WITHOUT cascade (using true intermediates)."""
    ch = LocalChallenge()
    actual_msg = ch.message
    ct_hex = ch.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    # Compute TRUE intermediates
    cipher = AES.new(ch.key, AES.MODE_ECB)
    true_inter2 = list(cipher.decrypt(bytes(c2)))
    true_inter1 = list(cipher.decrypt(bytes(c1)))

    correct = 0
    total = 0
    ch.query_count = 0

    budget = 200

    # Test block 2
    for pos in range(15, -1, -1):
        # Use TRUE intermediates for setup (no cascade)
        inter_for_setup = true_inter2[:]
        best_cand, _, used = find_byte_single(ch, c2, inter_for_setup, pos, c1[pos], budget)
        if best_cand == true_inter2[pos]:
            correct += 1
        total += 1

    # Test block 1
    for pos in range(15, -1, -1):
        inter_for_setup = true_inter1[:]
        best_cand, _, used = find_byte_single(ch, c1, inter_for_setup, pos, iv[pos], budget)
        if best_cand == true_inter1[pos]:
            correct += 1
        total += 1

    return correct, total, ch.query_count


def test_consensus_no_cascade():
    """Test multi-CT consensus accuracy WITHOUT cascade."""
    N_CTS = 3
    BUDGET_PER = 125

    ch = LocalChallenge()
    actual_msg = ch.message

    cts = []
    true_inters = []
    cipher_ecb = AES.new(ch.key, AES.MODE_ECB)

    for _ in range(N_CTS):
        ct_hex = ch.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        iv = list(ct_b[:16])
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cts.append((iv, c1, c2))
        true_inters.append((list(cipher_ecb.decrypt(bytes(c1))), list(cipher_ecb.decrypt(bytes(c2)))))

    ch.query_count = 0
    correct = 0
    total = 0

    # Test block 2
    for pos in range(15, -1, -1):
        votes = Counter()
        for ci in range(N_CTS):
            iv, c1, c2 = cts[ci]
            true_inter = true_inters[ci][1]
            best_cand, _, used = find_byte_single(ch, c2, true_inter, pos, c1[pos], BUDGET_PER)
            pt_byte = best_cand ^ c1[pos]
            votes[pt_byte] += 1

        consensus = votes.most_common(1)[0][0]
        actual_byte = ord(actual_msg[16 + (15 - pos)])  # Wait, ordering...
        # Actually plaintext byte at position pos in block 2
        actual_byte = ord(actual_msg[16 + pos])
        if consensus == actual_byte:
            correct += 1
        total += 1

    # Test block 1
    for pos in range(15, -1, -1):
        votes = Counter()
        for ci in range(N_CTS):
            iv, c1, c2 = cts[ci]
            true_inter = true_inters[ci][0]
            best_cand, _, used = find_byte_single(ch, c1, true_inter, pos, iv[pos], BUDGET_PER)
            pt_byte = best_cand ^ iv[pos]
            votes[pt_byte] += 1

        consensus = votes.most_common(1)[0][0]
        actual_byte = ord(actual_msg[pos])
        if consensus == actual_byte:
            correct += 1
        total += 1

    return correct, total, ch.query_count


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'single'
    n_trials = 50

    if mode == 'single':
        print("Testing per-byte accuracy (no cascade), budget=200/byte:")
        total_correct = 0
        total_bytes = 0
        for t in range(n_trials):
            c, n, q = test_single_ct_no_cascade()
            total_correct += c
            total_bytes += n
        print(f"Per-byte accuracy: {total_correct}/{total_bytes} = {100*total_correct/total_bytes:.1f}%")
        print(f"Per-32-byte success: ({total_correct/total_bytes}^32) = {(total_correct/total_bytes)**32*100:.1f}%")

    elif mode == 'consensus':
        print("Testing 3-CT consensus accuracy (no cascade), budget=125/byte/CT:")
        total_correct = 0
        total_bytes = 0
        for t in range(n_trials):
            c, n, q = test_consensus_no_cascade()
            total_correct += c
            total_bytes += n
        print(f"Per-byte accuracy: {total_correct}/{total_bytes} = {100*total_correct/total_bytes:.1f}%")
        print(f"Per-32-byte success: ({total_correct/total_bytes}^32) = {(total_correct/total_bytes)**32*100:.1f}%")
