"""
Smooth Criminal (60pts) — Elliptic Curves / Parameter Choice

The curve E : y² = x³ + 2x + 3  over  F_p  (p = 310717010502520989590157367261876774703)
has a fully smooth order:

    #E(F_p) = 310717010502520989590206149059164677804
           = 2² · 3⁷ · 139 · 165229 · 31850531 · 270778799 · 179317983307

The largest prime factor is ~37 bits (179317983307), so Pohlig-Hellman
plus per-subgroup BSGS recovers Alice's secret `n_a` in seconds.

The curve order is computed once via Sage (see order.sage — run with
`infra/sage-run.sh order.sage`), and cached in order.txt.
"""
import hashlib
import math
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from gmpy2 import mpz, invert
from sympy.ntheory.modular import crt

p  = mpz(310717010502520989590157367261876774703)
a  = mpz(2)
b  = mpz(3)
Gx = mpz(179210853392303317793440285562762725654)
Gy = mpz(105268671499942631758568591033409611165)
Ax = mpz(280810182131414898730378982766101210916)  # from output.txt
Ay = mpz(291506490768054478159835604632710368904)
Bx = mpz(272640099140026426377756188075937988094)  # Bob's public key
By = mpz(51062462309521034358726608268084433317)


def ec_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * invert(2 * y1, p) % p
    else:
        lam = (y2 - y1) * invert(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def ec_mul(P, n):
    if n == 0 or P is None:
        return None
    if n < 0:
        P = (P[0], (-P[1]) % p)
        n = -n
    R = None
    Q = P
    while n > 0:
        if n & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        n >>= 1
    return R


G = (Gx, Gy)
A = (Ax, Ay)
B_pt = (Bx, By)

# ==== Step 1: load curve order from Sage-generated file ====
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "order.txt")) as f:
    order = int(f.readline().strip())
    factors = []
    for line in f:
        q, e = line.split()
        factors.append((int(q), int(e)))

print(f"Curve order = {order}")
print(f"Factorization = {factors}")
assert ec_mul(G, order) is None, "G is not on the main subgroup of order `order`"


# ==== Step 2: Pohlig-Hellman ====
def bsgs(G_pt, A_pt, n):
    """Discrete log A_pt = x·G_pt in subgroup of order n."""
    if G_pt is None:
        return 0 if A_pt is None else None
    if A_pt is None:
        return 0
    m = int(math.isqrt(n)) + 1
    baby = {}
    cur = None
    for j in range(m):
        key = "O" if cur is None else (int(cur[0]), int(cur[1]))
        baby[key] = j
        cur = ec_add(cur, G_pt)
    neg_mG = ec_mul(G_pt, -m)
    gamma = A_pt
    for i in range(m + 1):
        key = "O" if gamma is None else (int(gamma[0]), int(gamma[1]))
        if key in baby:
            return (i * m + baby[key]) % n
        gamma = ec_add(gamma, neg_mG)
    return None


remainders, moduli = [], []
for q, e in factors:
    pe = q ** e
    cofactor = order // pe
    Gi = ec_mul(G, cofactor)
    Ai = ec_mul(A, cofactor)
    if Gi is None:
        continue
    # Actual order of Gi (in case Gi has lower order than pe)
    actual = pe
    test = Gi
    for _ in range(e):
        test = ec_mul(test, q)
        if test is None:
            break
    print(f"  Solving mod {q}^{e} (|Gi|={pe})...")
    xi = bsgs(Gi, Ai, pe)
    assert xi is not None
    remainders.append(int(xi))
    moduli.append(int(pe))

n_a, _ = crt(moduli, remainders)
print(f"n_a = {n_a}")
assert ec_mul(G, int(n_a)) == A, "n_a recovery failed"

# ==== Step 3: shared secret + decrypt ====
S = ec_mul(B_pt, int(n_a))
shared = int(S[0])
key = hashlib.sha1(str(shared).encode()).digest()[:16]
iv = bytes.fromhex("07e2628b590095a5e332d397b8a59aa7")
ct = bytes.fromhex(
    "8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d"
    "0870d3ac3a6ad80065c138a2ed6136af"
)
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print()
print("FLAG:", flag.decode())
