#!/usr/bin/env sage
# Micro Transmissions (EC / Parameter Choice, 120pts)
#
# nbits = 64 — private keys are only 64 bits. The full 256-bit curve has
# subexponentially-hard DLP, but a 64-bit secret means we can BSGS in
# O(2^32) ≈ 4·10^9 group ops, which Sage's bsgs(P, Q, bounds) handles in
# under a minute. Recover Alice's secret n_a, compute (n_a · B).x, derive
# the AES key, decrypt.

from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p  = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a  = 1
b  = 4
ax = 87360200456784002948566700858113190957688355783112995047798140117594305287669
bx = 6082896373499126624029343293750138460137531774473450341235217699497602895121
iv = bytes.fromhex("ceb34a8c174d77136455971f08641cc5")
ct = bytes.fromhex("b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453")

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]
print(f"[*] curve order = {E.order()}")
print(f"[*] G order     = {G.order()}")

# Recover Alice's public point (try both lifts of x)
A_candidates = [E.lift_x(ax)]
A_candidates.append(-A_candidates[0])

print(f"[*] BSGS for n_a (bounded ≤ 2^64)...")
n_a = None
for A in A_candidates:
    try:
        n_a = bsgs(G, A, (0, 2 ** 64))
        print(f"    found n_a = {n_a}  (using {'+' if A == A_candidates[0] else '-'}A)")
        break
    except ValueError:
        continue

if n_a is None:
    raise SystemExit("BSGS failed — try larger bound")

# Compute shared secret = (n_a · B).x  (sign of B doesn't change x-coordinate)
B = E.lift_x(bx)
shared = int((n_a * B).xy()[0])
print(f"[*] shared secret x = {shared}")

key = sha1(str(shared).encode("ascii")).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(f"FLAG: {flag.decode()}")
