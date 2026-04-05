"""
Multi-CT consensus approach with cascade elimination.
N CTs, consensus at each byte step, prevents cascade propagation.
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


def find_byte_for_ct(oracle_fn, target_block, inter, pos, prev_byte, budget):
    """Adaptive top-2 for a single CT."""
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    llr = [0.0] * 16
    used = 0

    # Screen: 2 queries per candidate
    screen_q = min(2, max(1, budget // 16))
    for idx in range(16):
        for _ in range(screen_q):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive top-2
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target_block, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], llr, used


def recover_block_consensus(oracle_fn, ct_data_list, budget_per_byte_per_ct):
    """
    Recover one 16-byte block using N CTs with consensus.
    ct_data_list: [(target_block, prev_block), ...]
    """
    N = len(ct_data_list)
    inters = [[0]*16 for _ in range(N)]
    plaintext = [0] * 16
    total_used = 0

    for pos in range(15, -1, -1):
        votes = Counter()

        for ci in range(N):
            target, prev = ct_data_list[ci]
            best_cand, llr, used = find_byte_for_ct(
                oracle_fn, target, inters[ci], pos, prev[pos], budget_per_byte_per_ct
            )
            total_used += used
            pt_byte = best_cand ^ prev[pos]
            votes[pt_byte] += 1

        # Consensus: pick most voted hex char
        consensus_pt = None
        for pt_byte, count in votes.most_common():
            if pt_byte in HEX_SET:
                consensus_pt = pt_byte
                break

        if consensus_pt is None:
            consensus_pt = votes.most_common(1)[0][0]

        plaintext[pos] = consensus_pt

        # Update intermediates for all CTs
        for ci in range(N):
            _, prev = ct_data_list[ci]
            inters[ci][pos] = consensus_pt ^ prev[pos]

    return plaintext, total_used


def solve(challenge, n_cts=21):
    """Main solve."""
    cts = []
    for _ in range(n_cts):
        ct_hex = challenge.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        iv = list(ct_b[:16])
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cts.append((iv, c1, c2))

    budget_per_byte_per_ct = 12000 // (n_cts * 32)

    # Block 2
    block2_data = [(ct[2], ct[1]) for ct in cts]
    pt2, q2 = recover_block_consensus(challenge.check_padding, block2_data, budget_per_byte_per_ct)

    # Block 1
    block1_data = [(ct[1], ct[0]) for ct in cts]
    pt1, q1 = recover_block_consensus(challenge.check_padding, block1_data, budget_per_byte_per_ct)

    return bytes(pt1 + pt2).decode('ascii', 'replace')


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    n_cts = int(sys.argv[2]) if len(sys.argv) > 2 else 21

    successes = 0
    wrongs = []
    total_start = time.time()

    for t in range(1, n_trials + 1):
        ch = LocalChallenge()
        recovered = solve(ch, n_cts=n_cts)
        ok = recovered == ch.message
        wrong = sum(1 for i in range(32) if recovered[i] != ch.message[i])

        if ok:
            successes += 1
        wrongs.append(wrong)

        if t % 200 == 0 or t == n_trials:
            elapsed = time.time() - total_start
            print(f"After {t}: {successes}/{t} ({100*successes/t:.1f}%) "
                  f"avg_wrong={sum(wrongs)/len(wrongs):.1f} "
                  f"time={elapsed:.0f}s")

    print(f"\nFinal: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    dist = Counter(wrongs)
    for k in sorted(dist):
        if dist[k] >= 5:
            print(f"  {k} wrong: {dist[k]} ({100*dist[k]/n_trials:.1f}%)")
