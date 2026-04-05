"""Debug: test interior byte (pos=10) with TRUE intermediates to ensure no cascade issue."""

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


def test_interior_byte():
    ch = LocalChallenge()
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
    true_inter = list(cipher_ecb.decrypt(bytes(c2)))

    pos = 10
    pad = 6  # 16 - 10

    cands = [c1[pos] ^ h for h in HEX_LIST]

    for i, cand in enumerate(cands):
        n_true = 0
        n_total = 200
        for _ in range(n_total):
            m = bytearray(os.urandom(16))
            # Set bytes 11..15 to true_inter[k] ^ pad
            for k in range(11, 16):
                m[k] = true_inter[k] ^ pad
            m[pos] = cand ^ pad
            ct_mod = (bytes(m) + bytes(c2)).hex()
            r = ch.check_padding(ct_mod)
            n_true += int(r)
        frac = n_true / n_total
        marker = " <-- TRUE" if cand == true_inter[pos] else ""
        print(f"  cand={cand:3d}: True={n_true:3d}/{n_total} = {frac:.2f}{marker}")


test_interior_byte()
