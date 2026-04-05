"""Trace a single trial to see what happens at each byte position."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
from collections import Counter

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']
HEX_SET = set(HEX_LIST)
LOG_P = math.log(0.4 / 0.6)


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
actual_msg = ch.message
print(f"Message: {actual_msg}")

N = 3  # CTs
cts = []
for _ in range(N):
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])
    cts.append((iv, c1, c2))

# Get true intermediates
cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
true_inters = []
for ct in cts:
    true_inters.append({
        'block1': list(cipher_ecb.decrypt(bytes(ct[1]))),
        'block2': list(cipher_ecb.decrypt(bytes(ct[2]))),
    })

# Test block 2 recovery
block_data = [(ct[2], ct[1]) for ct in cts]
inters = [[0]*16 for _ in range(N)]
budget = 125

ch.query_count = 0

# Just test pos=15 in detail
pos = 15
pad = 1
print(f"\n=== Byte position {pos}, pad={pad} ===")

for ci in range(N):
    target, prev = block_data[ci]
    true_inter_byte = true_inters[ci]['block2'][pos]
    cands = [prev[pos] ^ h for h in HEX_LIST]
    true_idx = cands.index(true_inter_byte)

    llr = [0.0] * 16
    counts = [0] * 16
    used = 0

    # Screen
    for idx in range(16):
        for _ in range(2):
            r = ch.check_padding(make_ct(target, inters[ci], pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            counts[idx] += 1
            used += 1

    # Adaptive top-2
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for target_idx in sorted_idx[:2]:
            if used >= budget:
                break
            r = ch.check_padding(make_ct(target, inters[ci], pos, pad, cands[target_idx]))
            llr[target_idx] += LOG_P if r else -LOG_P
            counts[target_idx] += 1
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    pt_byte = cands[best] ^ prev[pos]
    true_pt = true_inter_byte ^ prev[pos]

    print(f"\nCT{ci}: best_idx={best} cand={cands[best]} pt={chr(pt_byte) if 32<=pt_byte<127 else '?'} "
          f"(true_idx={true_idx} true_pt={chr(true_pt) if 32<=true_pt<127 else '?'})")
    print(f"  True cand LLR={llr[true_idx]:.2f} (n={counts[true_idx]})")
    print(f"  Best cand LLR={llr[best]:.2f} (n={counts[best]})")

    # Show top 4
    sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
    for i, idx in enumerate(sorted_idx[:4]):
        marker = " <-- TRUE" if idx == true_idx else ""
        print(f"    #{i+1}: cand[{idx}]={cands[idx]} llr={llr[idx]:+.2f} n={counts[idx]} pt={chr(cands[idx]^prev[pos]) if 32 <= cands[idx]^prev[pos] < 127 else '?'}{marker}")
