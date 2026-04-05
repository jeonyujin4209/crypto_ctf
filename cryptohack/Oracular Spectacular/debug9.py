"""Accurate per-byte testing with b=10 sequential halving."""

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


def find_byte(challenge, target, inter, pos, prev_byte, budget):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    scores = [0] * 16
    used = 0
    active = list(range(16))
    b = 10

    for n_active, keep in [(16, 8), (8, 4), (4, 2)]:
        for idx in active:
            for _ in range(b):
                if used >= budget:
                    break
                r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
                scores[idx] += (-1 if r else 1)
                used += 1
        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:keep]

    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)
            used += 1

    best = max(active, key=lambda i: scores[i])
    return cands[best], used


# Test per byte with correct intermediates
n_trials = 2000
budget = 370
correct_count = 0
elim_in_round = [0, 0, 0, 0]  # Track where errors come from

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
    b = 10
    eliminated_round = -1

    for rnd, (n_active, keep) in enumerate([(16, 8), (8, 4), (4, 2)]):
        for idx in active:
            for _ in range(b):
                r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cands[idx]))
                scores[idx] += (-1 if r else 1)
                used += 1
        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:keep]
        if true_idx not in active and eliminated_round < 0:
            eliminated_round = rnd

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
    elif eliminated_round >= 0:
        elim_in_round[eliminated_round] += 1
    else:
        elim_in_round[3] += 1  # Lost in final duel

accuracy = correct_count / n_trials
print(f"Budget={budget}, b=10, n={n_trials}")
print(f"Accuracy: {correct_count}/{n_trials} = {100*accuracy:.1f}%")
print(f"Elimination breakdown: R0={elim_in_round[0]} R1={elim_in_round[1]} R2={elim_in_round[2]} Final={elim_in_round[3]}")
print(f"P(32 bytes correct): {accuracy**32*100:.2f}%")
