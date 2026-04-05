"""Fundamental check: verify the response distribution for correct vs wrong candidates."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']


class LocalChallenge:
    def __init__(self):
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0

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

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return (iv + ct).hex()


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


# Test with FOUND intermediates (with cascade) vs TRUE intermediates
ch = LocalChallenge()
ct_hex = ch.get_ct()
ct_b = bytes.fromhex(ct_hex)
iv = list(ct_b[:16])
c1 = list(ct_b[16:32])
c2 = list(ct_b[32:48])

cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
true_inter = list(cipher_ecb.decrypt(bytes(c2)))

print("Testing byte 15 (pad=1) with TRUE intermediates:")
# No prior intermediates needed for byte 15
pos = 15
pad = 1
true_cand = true_inter[pos]
wrong_cand = true_cand ^ 1  # any wrong value

n = 500
true_results = []
wrong_results = []

for _ in range(n):
    r_true = ch.check_padding(make_ct(c2, true_inter, pos, pad, true_cand))
    r_wrong = ch.check_padding(make_ct(c2, true_inter, pos, pad, wrong_cand))
    true_results.append(int(r_true))
    wrong_results.append(int(r_wrong))

print(f"  True cand: P(True)={sum(true_results)/n:.3f} (expect 0.4)")
print(f"  Wrong cand: P(True)={sum(wrong_results)/n:.3f} (expect 0.6)")

# Now test with WRONG intermediate for byte 15, checking byte 14
print("\nTesting byte 14 (pad=2) with WRONG intermediate at byte 15:")
wrong_inter = true_inter[:]
wrong_inter[15] = true_inter[15] ^ 0x42  # deliberately wrong

pos = 14
pad = 2
true_cand14 = true_inter[pos]
wrong_cand14 = true_cand14 ^ 1

true_results = []
wrong_results = []

for _ in range(n):
    r_true = ch.check_padding(make_ct(c2, wrong_inter, pos, pad, true_cand14))
    r_wrong = ch.check_padding(make_ct(c2, wrong_inter, pos, pad, wrong_cand14))
    true_results.append(int(r_true))
    wrong_results.append(int(r_wrong))

print(f"  True cand (with wrong inter[15]): P(True)={sum(true_results)/n:.3f}")
print(f"  Wrong cand (with wrong inter[15]): P(True)={sum(wrong_results)/n:.3f}")
print("  (Both should be ~0.6 since padding is always invalid)")

# Verify: with correct inter, byte 14 works
print("\nTesting byte 14 (pad=2) with CORRECT intermediate at byte 15:")
pos = 14
pad = 2

true_results = []
wrong_results = []

for _ in range(n):
    r_true = ch.check_padding(make_ct(c2, true_inter, pos, pad, true_cand14))
    r_wrong = ch.check_padding(make_ct(c2, true_inter, pos, pad, wrong_cand14))
    true_results.append(int(r_true))
    wrong_results.append(int(r_wrong))

print(f"  True cand (correct inter[15]): P(True)={sum(true_results)/n:.3f} (expect 0.4)")
print(f"  Wrong cand (correct inter[15]): P(True)={sum(wrong_results)/n:.3f} (expect 0.6)")
