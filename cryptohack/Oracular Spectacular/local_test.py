"""Local test harness - runs the solve algorithm against a local Challenge instance.
No network needed. Can see the actual message for debugging."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
import sys
import time

rng = SystemRandom()
HEX_CHARS = [ord(c) for c in '0123456789abcdef']


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
        return good ^ (rng.random() > 0.4)

    def check_message(self, message):
        return message == self.message


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def candidate_llr(t, n):
    if n == 0:
        return 0.0
    LOG_RATIO = math.log(0.4 / 0.6)  # -0.405
    return t * LOG_RATIO + (n - t) * (-LOG_RATIO)


def find_byte(challenge, target, inter, pos, prev, budget):
    """Independent LLR with Sequential Halving style allocation."""
    pad = 16 - pos
    cands = [prev[pos] ^ h for h in HEX_CHARS]
    n_cands = len(cands)

    t_count = [0] * n_cands
    n_count = [0] * n_cands
    used = 0
    active = list(range(n_cands))

    # Sequential Halving: ceil(log2(16)) = 4 rounds
    # Budget split: ~6, ~12, ~24, ~rest per candidate
    rounds_config = [
        (6, n_cands // 2),     # 6 queries each, keep top 8
        (12, None),            # 12 more, keep top 4
        (24, None),            # 24 more, keep top 2
    ]

    for rnd, (q_per, keep_n) in enumerate(rounds_config):
        if keep_n is None:
            keep_n = max(2, len(active) // 2)

        for idx in active:
            for _ in range(q_per):
                if used >= budget:
                    break
                result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                t_count[idx] += int(result)
                n_count[idx] += 1
                used += 1

        # Rank by LLR (higher = more valid-like)
        llrs = [candidate_llr(t_count[i], n_count[i]) for i in range(n_cands)]
        active.sort(key=lambda i: llrs[i], reverse=True)
        active = active[:keep_n]

    # Final duel with remaining budget
    while used < budget and len(active) >= 2:
        for idx in active:
            if used >= budget:
                break
            result = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            t_count[idx] += int(result)
            n_count[idx] += 1
            used += 1

    llrs = [candidate_llr(t_count[i], n_count[i]) for i in range(n_cands)]
    best = max(active, key=lambda i: llrs[i])
    return cands[best], used


def recover_block(challenge, target, prev, budget_per_byte):
    inter = [0] * 16
    total_used = 0
    for pos in range(15, -1, -1):
        winner, used = find_byte(challenge, target, inter, pos, prev, budget_per_byte)
        inter[pos] = winner
        total_used += used
        pt = winner ^ prev[pos]
        ch = chr(pt) if 32 <= pt < 127 else '?'
        sys.stdout.write(f"  [{pos:2d}]='{ch}' q={used}  ")
        if pos % 4 == 0:
            sys.stdout.write("\n")
    sys.stdout.flush()
    return inter, total_used


def run_test(budget_per_byte=370):
    ch = LocalChallenge()
    actual_msg = ch.message
    ct_hex = ch.get_ct()
    ct_bytes = bytes.fromhex(ct_hex)
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    ch.query_count = 0

    # Block 2
    i2, q2 = recover_block(ch, c2, c1, budget_per_byte)
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])

    # Block 1
    i1, q1 = recover_block(ch, c1, iv, budget_per_byte)
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])

    recovered = (pt1 + pt2).decode('ascii', 'replace')
    total_q = ch.query_count

    # Compare byte by byte
    wrong_bytes = []
    for i in range(32):
        if recovered[i] != actual_msg[i]:
            wrong_bytes.append(i)

    return {
        'actual': actual_msg,
        'recovered': recovered,
        'correct': recovered == actual_msg,
        'wrong_count': len(wrong_bytes),
        'wrong_positions': wrong_bytes,
        'queries': total_q,
    }


if __name__ == '__main__':
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    budget = int(sys.argv[2]) if len(sys.argv) > 2 else 370

    successes = 0
    wrong_counts = []
    total_start = time.time()

    for trial in range(1, n_trials + 1):
        start = time.time()
        result = run_test(budget)
        elapsed = time.time() - start

        status = "OK" if result['correct'] else f"FAIL ({result['wrong_count']} wrong: {result['wrong_positions'][:5]}...)"
        print(f"\nTrial {trial}/{n_trials}: {status}  q={result['queries']}  {elapsed:.1f}s")
        print(f"  actual:    {result['actual']}")
        print(f"  recovered: {result['recovered']}")

        if result['correct']:
            successes += 1
        wrong_counts.append(result['wrong_count'])

    total_time = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"Results: {successes}/{n_trials} success ({100*successes/n_trials:.1f}%)")
    print(f"Wrong byte distribution: {dict((k, wrong_counts.count(k)) for k in sorted(set(wrong_counts)))}")
    print(f"Total time: {total_time:.1f}s ({total_time/n_trials:.1f}s per trial)")
