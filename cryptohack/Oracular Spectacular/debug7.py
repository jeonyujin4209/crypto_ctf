"""Fundamental debug: check raw oracle responses for correct vs incorrect candidates."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os

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


ch = LocalChallenge()
ct_hex = ch.get_ct()
ct_b = bytes.fromhex(ct_hex)
c1 = list(ct_b[16:32])
c2 = list(ct_b[32:48])
cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
true_inter = list(cipher_ecb.decrypt(bytes(c2)))

# Test pos=15 with 1000 queries per candidate
pos = 15
pad = 1
cands = [c1[pos] ^ h for h in HEX_LIST]
true_idx = cands.index(true_inter[pos])

print(f"Testing pos=15, pad=1, true_idx={true_idx}, true_cand={true_inter[pos]}")

for i, cand in enumerate(cands):
    n_true = 0
    n_total = 500
    for _ in range(n_total):
        r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cand))
        n_true += int(r)
    frac = n_true / n_total
    score = n_total - 2 * n_true  # false - true
    marker = " <-- TRUE" if i == true_idx else ""
    print(f"  cand[{i:2d}]={cand:3d}: True%={frac:.3f} score={score:+4d}{marker}")

# Now test pos=8 (pad=8)
print()
pos = 8
pad = 8
cands = [c1[pos] ^ h for h in HEX_LIST]
true_idx = cands.index(true_inter[pos])

print(f"Testing pos=8, pad=8, true_idx={true_idx}, true_cand={true_inter[pos]}")

for i, cand in enumerate(cands):
    n_true = 0
    n_total = 500
    for _ in range(n_total):
        r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cand))
        n_true += int(r)
    frac = n_true / n_total
    score = n_total - 2 * n_true
    marker = " <-- TRUE" if i == true_idx else ""
    print(f"  cand[{i:2d}]={cand:3d}: True%={frac:.3f} score={score:+4d}{marker}")
