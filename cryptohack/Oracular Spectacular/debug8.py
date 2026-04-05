"""Instrument the sequential halving to see what goes wrong."""

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

    def check_padding_noiseless(self, ct_hex):
        """For debugging: noiseless oracle."""
        ct = bytes.fromhex(ct_hex)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
        except ValueError:
            return False
        else:
            return True


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


# Run ONE byte-finding instance with instrumentation
ch = LocalChallenge()
ct_hex = ch.get_ct()
ct_b = bytes.fromhex(ct_hex)
c1 = list(ct_b[16:32])
c2 = list(ct_b[32:48])
cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
true_inter = list(cipher_ecb.decrypt(bytes(c2)))

pos = 15
pad = 1
budget = 370
b = 10

cands = [c1[pos] ^ h for h in HEX_LIST]
true_idx = cands.index(true_inter[pos])
scores = [0] * 16
active = list(range(16))

print(f"True candidate: idx={true_idx}, cand={cands[true_idx]}")

# Check: which candidates actually give valid padding?
print("\nNoiseless check for pos=15:")
for i, cand in enumerate(cands):
    # For pos=15, pad=1, we only set m[15] = cand ^ 1, rest random
    n_valid = 0
    for _ in range(100):
        ct_mod = make_ct(c2, true_inter, pos, pad, cand)
        valid = ch.check_padding_noiseless(ct_mod)
        n_valid += int(valid)
    print(f"  cand[{i:2d}]={cand:3d}: valid {n_valid}/100 {'<-- TRUE' if i==true_idx else ''}")

# Now do sequential halving
print(f"\nSequential halving with b={b}:")
used = 0

for rnd, (n_active, keep) in enumerate([(16, 8), (8, 4), (4, 2)]):
    for idx in active:
        for _ in range(b):
            r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)
            used += 1

    print(f"\nRound {rnd}: {n_active}→{keep}")
    for idx in active:
        marker = " <-- TRUE" if idx == true_idx else ""
        print(f"  cand[{idx:2d}]={cands[idx]:3d}: score={scores[idx]:+4d}{marker}")

    active.sort(key=lambda i: scores[i], reverse=True)
    print(f"  Keeping top {keep}: {active[:keep]}")
    print(f"  True in kept: {true_idx in active[:keep]}")
    active = active[:keep]

# Final duel
remaining = budget - used
print(f"\nFinal duel: {remaining} queries for {len(active)} candidates")
while used < budget:
    for idx in active:
        if used >= budget:
            break
        r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cands[idx]))
        scores[idx] += (-1 if r else 1)
        used += 1

best = max(active, key=lambda i: scores[i])
print(f"Result: best=cand[{best}]={cands[best]}, correct={'YES' if best==true_idx else 'NO'}")
for idx in active:
    marker = " <-- TRUE" if idx == true_idx else ""
    print(f"  cand[{idx:2d}]: score={scores[idx]:+4d}{marker}")
