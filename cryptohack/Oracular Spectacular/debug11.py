"""Test with noiseless oracle to verify code correctness."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import os
import random

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']


class NoiselessChallenge:
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
        return good  # No noise!


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


# Single query per candidate should work with noiseless oracle
n_trials = 100
correct = 0

for _ in range(n_trials):
    ch = NoiselessChallenge()
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

    found = None
    for i, cand in enumerate(cands):
        # With noiseless oracle, valid = True means this is the correct candidate
        # Actually, valid padding means True is returned
        # For the correct cand, P(True) = 1
        # For wrong cand, P(True) should be near 0 but might have false positives
        r = ch.check_padding(make_ct(c2, true_inter, pos, pad, cand))
        if r:
            found = cand
            break

    if found == true_inter[pos]:
        correct += 1
    else:
        if found is None:
            print(f"No candidate gave True! pos={pos}, pad={pad}")
        else:
            true_idx = cands.index(true_inter[pos])
            found_idx = cands.index(found)
            print(f"Wrong candidate! pos={pos}, pad={pad}, true_idx={true_idx}, found_idx={found_idx}")
            # Check if true candidate gives True
            r = ch.check_padding(make_ct(c2, true_inter, pos, pad, true_inter[pos]))
            print(f"  True candidate gives: {r}")

print(f"\nNoiseless accuracy: {correct}/{n_trials} = {100*correct/n_trials:.1f}%")
