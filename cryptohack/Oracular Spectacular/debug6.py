"""Check per-byte accuracy by position (pos=15 vs pos=0)."""

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


def find_byte(challenge, target, inter, pos, prev_byte, budget):
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_LIST]
    scores = [0] * 16
    used = 0
    active = list(range(16))

    q1 = min(8, budget // 16)
    for idx in active:
        for _ in range(q1):
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)
            used += 1
    active.sort(key=lambda i: scores[i], reverse=True)
    active = active[:4]

    while used < budget:
        for idx in active:
            if used >= budget:
                break
            r = challenge.check_padding(make_ct(target, inter, pos, pad, cands[idx]))
            scores[idx] += (-1 if r else 1)
            used += 1

    best = max(active, key=lambda i: scores[i])
    return cands[best], used


n_trials = 300
budget = 125

for pos in [15, 12, 8, 4, 0]:
    correct = 0
    for _ in range(n_trials):
        ch = LocalChallenge()
        ct_hex = ch.get_ct()
        ct_b = bytes.fromhex(ct_hex)
        c1 = list(ct_b[16:32])
        c2 = list(ct_b[32:48])
        cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
        true_inter = list(cipher_ecb.decrypt(bytes(c2)))

        best, _ = find_byte(ch, c2, true_inter, pos, c1[pos], budget)
        if best == true_inter[pos]:
            correct += 1

    print(f"pos={pos:2d} (pad={16-pos:2d}): accuracy={correct}/{n_trials} = {100*correct/n_trials:.1f}%")
