"""Debug a single block recovery to see what goes wrong."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os
import sys

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


def find_byte_debug(challenge, target, inter, pos, prev_byte, budget, true_inter_byte):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]

    scores = [0] * 16
    n_queries = [0] * 16
    used = 0
    active = list(range(16))

    rounds = [(5, 8), (10, 4), (20, 2)]

    for rnd, (q_each, keep) in enumerate(rounds):
        for idx in active:
            for _ in range(q_each):
                if used >= budget:
                    break
                r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                if r:
                    scores[idx] -= 1
                else:
                    scores[idx] += 1
                n_queries[idx] += 1
                used += 1
        active.sort(key=lambda i: scores[i], reverse=True)

        # Find where true candidate is
        true_idx = cands.index(true_inter_byte) if true_inter_byte in cands else -1
        true_rank = active.index(true_idx) if true_idx in active else -1

        print(f"  Round {rnd}: active={len(active)}, true_idx={true_idx}, true_rank={true_rank}/{len(active)}")
        if true_idx >= 0 and true_idx in active:
            print(f"    true score={scores[true_idx]} (n={n_queries[true_idx]}), "
                  f"best score={scores[active[0]]} (n={n_queries[active[0]]})")

        active = active[:keep]
        if true_idx >= 0 and true_idx not in active:
            print(f"    *** TRUE CANDIDATE ELIMINATED at round {rnd}! ***")

    # Final duel
    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            if r:
                scores[idx] -= 1
            else:
                scores[idx] += 1
            n_queries[idx] += 1
            used += 1

    best = max(active, key=lambda i: scores[i])

    true_idx = cands.index(true_inter_byte) if true_inter_byte in cands else -1
    print(f"  Final: best=cand[{best}]={cands[best]}, true=cand[{true_idx}]={true_inter_byte}")
    print(f"    best score={scores[best]} (n={n_queries[best]})")
    if true_idx >= 0:
        print(f"    true score={scores[true_idx]} (n={n_queries[true_idx]})")
    print(f"    CORRECT: {cands[best] == true_inter_byte}")

    return cands[best], used


ch = LocalChallenge()
actual_msg = ch.message
print(f"Message: {actual_msg}")

ct_hex = ch.get_ct()
ct_b = bytes.fromhex(ct_hex)
iv = list(ct_b[:16])
c1 = list(ct_b[16:32])
c2 = list(ct_b[32:48])

cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
true_inter2 = list(cipher_ecb.decrypt(bytes(c2)))
true_inter1 = list(cipher_ecb.decrypt(bytes(c1)))

ch.query_count = 0

# Recover block 2
inter = [0] * 16
for pos in range(15, -1, -1):
    print(f"\nByte pos={pos}, pad={16-pos}")
    best, used = find_byte_debug(ch, c2, inter, pos, c1[pos], 370, true_inter2[pos])
    inter[pos] = best
    if best != true_inter2[pos]:
        print(f"  !!! ERROR: got {best}, true={true_inter2[pos]}. Cascade will corrupt subsequent bytes.")
