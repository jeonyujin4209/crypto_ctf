#!/usr/bin/env sage
# Stage 1 (Sage): bounded BSGS for n_a, write secret + (n_a·B).x to file.
# Then host Python decrypts the AES flag (Sage container doesn't have pycryptodome).

p  = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a  = 1
b  = 4
ax = 87360200456784002948566700858113190957688355783112995047798140117594305287669
bx = 6082896373499126624029343293750138460137531774473450341235217699497602895121

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]
print(f"[*] G order = {G.order()}")

A_candidates = [E.lift_x(ax)]
A_candidates.append(-A_candidates[0])

from sage.groups.generic import bsgs
print("[*] BSGS for n_a, bound 2^64...")
n_a = None
for sign, A in zip(("+", "-"), A_candidates):
    try:
        n_a = bsgs(G, A, (0, 2 ** 64), operation="+")
        print(f"    found n_a = {n_a}  (sign {sign})")
        break
    except ValueError:
        pass

if n_a is None:
    raise SystemExit("BSGS failed")

B = E.lift_x(bx)
shared = int((int(n_a) * B).xy()[0])
print(f"[*] shared secret x = {shared}")

with open("dlog_out.txt", "w") as f:
    f.write(str(int(n_a)) + "\n")
    f.write(str(shared) + "\n")
print("[+] wrote dlog_out.txt")
