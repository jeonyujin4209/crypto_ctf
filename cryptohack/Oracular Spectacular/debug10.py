"""Test different sequential halving strategies."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os
import random

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


def test_strategy(strategy_name, rounds_config, budget, n_trials=2000):
    """Test a halving strategy. rounds_config = [(keep, q_per_cand), ...]"""
    correct_count = 0

    for t in range(n_trials):
        ch = LocalChallenge()
        ct_hex = ch.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
        true_inter = list(cipher_ecb.decrypt(bytes(c2)))

        pos = random.randint(0, 15)
        pad = 16 - pos
        prev_byte = c1[pos]
        cands = [prev_byte ^ h for h in HEX_LIST]
        true_idx = cands.index(true_inter[pos])

        scores = [0] * 16
        used = 0
        active = list(range(16))

        for keep, q_per in rounds_config:
            for idx in active:
                for _ in range(q_per):
                    if used >= budget:
                        break
                    r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cands[idx]))
                    scores[idx] += (-1 if r else 1)
                    used += 1
            active.sort(key=lambda i: scores[i], reverse=True)
            active = active[:keep]

        # Final: remaining budget on surviving candidates
        while used < budget:
            for idx in active:
                if used >= budget:
                    break
                r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cands[idx]))
                scores[idx] += (-1 if r else 1)
                used += 1

        best = max(active, key=lambda i: scores[i])
        if best == true_idx:
            correct_count += 1

    accuracy = correct_count / n_trials
    print(f"{strategy_name:30s}: {100*accuracy:.1f}% per-byte → {accuracy**32*100:.2f}% per-32")


budget = 370

# Strategy 1: 16→8→4→2, b=10 (current)
test_strategy("16→8→4→2, b=10", [(8, 10), (4, 10), (2, 10)], budget)

# Strategy 2: 16→4→2, b=15 then b=15
# 16*15 + 4*15 + 2*final = 240+60+remaining(70) = 370
test_strategy("16→4→2, b=15", [(4, 15), (2, 15)], budget)

# Strategy 3: 16→4, b=20, then final
# 16*20 + 4*final_each. 320 + 4*12.5 = 370
test_strategy("16→4, b=20", [(4, 20)], budget)

# Strategy 4: 16→2, b=10, then final
# 16*10 + 2*final = 160 + 210, final = 105 each
test_strategy("16→2, b=10", [(2, 10)], budget)

# Strategy 5: 16→8→2, b=10
test_strategy("16→8→2, b=10", [(8, 10), (2, 10)], budget)

# Strategy 6: 16→8→2, b=15
# 16*15 + 8*15 + 2*final = 240+120+10. final = 5 each
test_strategy("16→8→2, b=15", [(8, 15), (2, 15)], budget)

# Strategy 7: 16→4, b=15, then final
# 16*15 + 4*final = 240 + 130, final = 32 each
test_strategy("16→4, b=15", [(4, 15)], budget)

# Strategy 8: LUCA's formula - spend proportionally
# Round 1: 16 cands, use budget_factor * log2(16) portion
# Simpler: 16→4 with 20 queries, then 4→1 with remaining
test_strategy("16→4(20) → 1", [(4, 20), (1, 0)], budget)

# Strategy 9: 16→2 with 15 queries each
# 16*15 = 240, remaining 130, 65 each for top 2
test_strategy("16→2, b=15", [(2, 15)], budget)

# Strategy 10: 16→3 with b=15
# 16*15 = 240, remaining 130, ~43 each for top 3... but final picks 1
test_strategy("16→3, b=15", [(3, 15)], budget)
