"""Measure false positive rate for wrong candidates with random prefix."""

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

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return (iv + ct).hex()

    def check_padding_noiseless(self, ct_hex):
        ct = bytes.fromhex(ct_hex)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
            return True
        except ValueError:
            return False


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


# Check false positive rate per position
for pos in [15, 14, 10, 5, 0]:
    pad = 16 - pos
    n_valid_wrong = 0
    n_total_wrong = 0
    n_valid_correct = 0
    n_total_correct = 0

    for _ in range(100):
        ch = LocalChallenge()
        ct_hex = ch.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
        true_inter = list(cipher_ecb.decrypt(bytes(c2)))

        cands = [c1[pos] ^ h for h in HEX_LIST]
        true_idx = cands.index(true_inter[pos])

        for i, cand in enumerate(cands):
            for _ in range(100):
                r = ch.check_padding_noiseless(make_ct(c2, true_inter, pos, pad, cand))
                if i == true_idx:
                    n_valid_correct += int(r)
                    n_total_correct += 1
                else:
                    n_valid_wrong += int(r)
                    n_total_wrong += 1

    fp_rate = n_valid_wrong / n_total_wrong if n_total_wrong > 0 else 0
    tp_rate = n_valid_correct / n_total_correct if n_total_correct > 0 else 0
    print(f"pos={pos:2d} (pad={pad:2d}): FP rate={fp_rate:.4f}  TP rate={tp_rate:.4f}")
    # FP means: wrong candidate but padding still valid
    # For wrong cand, expected FP rate should be very low
    # Effective P(True|wrong) = FP×0.4 + (1-FP)×0.6
