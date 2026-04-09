"""
Smooth Criminal solver.
The curve E: y^2 = x^3 + 2x + 3 over Fp (p=310717010502520989590157367261876774703)
has a smooth curve order, allowing Pohlig-Hellman to solve the ECDLP.

To complete: compute the curve order using Sage:
  p = 310717010502520989590157367261876774703
  E = EllipticCurve(GF(p), [2, 3])
  print(E.order())
  print(factor(E.order()))
Then paste the order and factors below.

Without Sage: run the smooth-number test (may take hours) to find the order.
"""
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import gmpy2
from gmpy2 import mpz, invert, next_prime
import math
import time
from sympy import factorint, primerange
from sympy.ntheory.modular import crt

p = mpz(310717010502520989590157367261876774703)
a = mpz(2)
b = mpz(3)

Gx = mpz(179210853392303317793440285562762725654)
Gy = mpz(105268671499942631758568591033409611165)
Ax = mpz(280810182131414898730378982766101210916)
Ay = mpz(291506490768054478159835604632710368904)
Bx = mpz(272640099140026426377756188075937988094)
By = mpz(51062462309521034358726608268084433317)

def ec_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2:
        if (y1 + y2) % p == 0: return None
        lam = (3*x1*x1 + a) * invert(2*y1, p) % p
    else:
        lam = (y2 - y1) * invert(x2 - x1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(P, n):
    if n == 0 or P is None: return None
    if n < 0: P = (P[0], (-P[1]) % p); n = -n
    R = None; Q = P
    while n > 0:
        if n & 1: R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        n >>= 1
    return R

G = (Gx, Gy)
A = (Ax, Ay)
B = (Bx, By)

# ===== STEP 1: Find curve order =====
# Try smooth-number approach: multiply G by all prime powers and check if we hit O
upper = int(p) + 1 + 2 * int(gmpy2.isqrt(p))

print("Finding curve order via smooth number test...", flush=True)
start = time.time()
P = G
q = mpz(2)
count = 0
max_prime = mpz(5000000000)

while q <= max_prime:
    qk = int(q)
    while qk * int(q) <= upper:
        qk *= int(q)
    P = ec_mul(P, qk)
    if P is None:
        print(f'Order is {q}-smooth! (took {time.time()-start:.1f}s)', flush=True)
        break
    count += 1
    if count % 1000000 == 0:
        print(f'  Checked primes up to {q}, {time.time()-start:.1f}s', flush=True)
    q = next_prime(q)

if P is not None:
    print(f"Not {max_prime}-smooth. Need Sage to compute order.", flush=True)
    print("Run in Sage:", flush=True)
    print(f"  E = EllipticCurve(GF({int(p)}), [{int(a)}, {int(b)}])", flush=True)
    print(f"  print(E.order())", flush=True)
    sys.exit(1)

# Find exact order
print("Computing exact order...", flush=True)
N = 1
for qi in primerange(2, int(q) + 1):
    qk = int(qi)
    while qk * qi <= upper:
        qk *= qi
    N *= qk
order = N
for qi in primerange(2, int(q) + 1):
    while order % qi == 0:
        if ec_mul(G, order // qi) is None:
            order //= qi
        else:
            break

factors = factorint(order)
print(f"Order = {order}", flush=True)
print(f"Factors = {factors}", flush=True)

# ===== STEP 2: Pohlig-Hellman =====
def bsgs(G_pt, A_pt, n):
    if G_pt is None: return 0 if A_pt is None else None
    if A_pt is None: return 0
    m = int(math.isqrt(n)) + 1
    baby = {}; cur = None
    for j in range(m):
        key = 'O' if cur is None else (int(cur[0]), int(cur[1]))
        baby[key] = j
        cur = ec_add(cur, G_pt)
    neg_mG = ec_mul(G_pt, -m)
    if neg_mG is None:
        key = 'O' if A_pt is None else (int(A_pt[0]), int(A_pt[1]))
        return baby.get(key)
    gamma = A_pt
    for i in range(m + 1):
        key = 'O' if gamma is None else (int(gamma[0]), int(gamma[1]))
        if key in baby: return (i * m + baby[key]) % n
        gamma = ec_add(gamma, neg_mG)
    return None

print("\nPohlig-Hellman for n_a...", flush=True)
remainders = []
moduli = []
for prime, exp in factors.items():
    pe = prime ** exp
    cofactor = order // pe
    Gi = ec_mul(G, cofactor)
    Ai = ec_mul(A, cofactor)
    if Gi is None:
        continue
    actual_ord = pe
    test = Gi
    for e in range(1, exp + 1):
        test = ec_mul(test, prime)
        if test is None:
            actual_ord = prime ** e
            break
    print(f"  Solving mod {prime}^{exp} (actual order={actual_ord})...", flush=True)
    xi = bsgs(Gi, Ai, actual_ord)
    if xi is not None:
        remainders.append(int(xi))
        moduli.append(int(actual_ord))
        print(f"  x = {xi} mod {actual_ord}", flush=True)

n_a, _ = crt(moduli, remainders)
print(f"\nn_a = {n_a}", flush=True)

check = ec_mul(G, int(n_a))
print(f"Verify: {check == A}", flush=True)

# ===== STEP 3: Decrypt =====
S = ec_mul(B, int(n_a))
shared = int(S[0])

sha1 = hashlib.sha1()
sha1.update(str(shared).encode('ascii'))
key = sha1.digest()[:16]
iv = bytes.fromhex('07e2628b590095a5e332d397b8a59aa7')
ct = bytes.fromhex('8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af')
cipher = AES.new(key, AES.MODE_CBC, iv)
try:
    flag = unpad(cipher.decrypt(ct), 16)
    print(f"Flag: {flag.decode()}", flush=True)
except ValueError:
    print("Padding error, try p - n_a", flush=True)
    S2 = ec_mul(B, order - int(n_a))
    sha1 = hashlib.sha1()
    sha1.update(str(int(S2[0])).encode('ascii'))
    key = sha1.digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ct), 16)
    print(f"Flag: {flag.decode()}", flush=True)
