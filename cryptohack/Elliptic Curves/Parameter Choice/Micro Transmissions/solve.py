"""
Micro Transmissions solver.
Private key is only 64 bits on a 256-bit curve.
Use BSGS with 2^32 baby/giant steps to find the key.

Requires gmpy2 for fast modular arithmetic.
The computation takes ~1.5 hours with gmpy2 on a modern CPU.

Alternative: if Sage is available, compute curve order and use Pohlig-Hellman
if the order has enough small factors to cover 64 bits.
"""
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import gmpy2
from gmpy2 import mpz, invert, powmod
import time
import math

p = mpz(99061670249353652702595159229088680425828208953931838069069584252923270946291)
a_coeff = mpz(1)
b_coeff = mpz(4)

Gx = mpz(43190960452218023575787899214023014938926631792651638044680168600989609069200)
Gy = mpz(20971936269255296908588589778128791635639992476076894152303569022736123671173)
ax_pub = mpz(87360200456784002948566700858113190957688355783112995047798140117594305287669)
bx_pub = mpz(6082896373499126624029343293750138460137531774473450341235217699497602895121)

iv_hex = 'ceb34a8c174d77136455971f08641cc5'
ct_hex = 'b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453'

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0: return None
        lam = (3*x1*x1 + a_coeff) * invert(2*y1, p) % p
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

def mod_sqrt(n, p):
    """Tonelli-Shanks modular square root."""
    n = n % p
    if n == 0: return mpz(0)
    if powmod(n, (p-1)//2, p) != 1: return None
    q = p - 1; s = 0
    while q % 2 == 0: q //= 2; s += 1
    if s == 1: return powmod(n, (p+1)//4, p)
    z = mpz(2)
    while powmod(z, (p-1)//2, p) != p - 1: z += 1
    M = s; c = powmod(z, q, p); t = powmod(n, q, p); R = powmod(n, (q+1)//2, p)
    while True:
        if t == 1: return R
        i = 1; temp = t * t % p
        while temp != 1: temp = temp * temp % p; i += 1
        b = c
        for _ in range(M - i - 1): b = b * b % p
        M = i; c = b * b % p; t = t * c % p; R = R * b % p

G = (Gx, Gy)

# Compute Alice and Bob's full points
y2a = (ax_pub**3 + a_coeff * ax_pub + b_coeff) % p
ay = mod_sqrt(y2a, p)

y2b = (bx_pub**3 + a_coeff * bx_pub + b_coeff) % p
by = mod_sqrt(y2b, p)

print(f"Alice y computed, Bob y computed", flush=True)

# BSGS: find n_a such that n_a * G = (ax_pub, ay_val), n_a < 2^64
# m = 2^32, baby steps: m entries, giant steps: up to m steps
m = 1 << 32

for ay_val in [ay, p - ay]:
    A = (ax_pub, ay_val)

    print(f"\nBSGS with y = ...{str(ay_val)[-10:]}", flush=True)
    print(f"Building baby table (m = {m} = 2^32)...", flush=True)

    start = time.time()
    baby = {}
    cur = None
    for j in range(m):
        xkey = 0 if cur is None else int(cur[0])
        baby[xkey] = j
        cur = ec_add(cur, G) if j > 0 else G
        if j > 0 and j % 10000000 == 0:
            elapsed = time.time() - start
            rate = j / elapsed
            eta = (m - j) / rate
            print(f"  Baby {j}/{m} ({j*100//m}%), {rate:.0f} ops/s, ETA: {eta/3600:.1f}h", flush=True)

    print(f"Baby done: {(time.time()-start)/3600:.2f}h, {len(baby)} entries", flush=True)

    print("Giant steps...", flush=True)
    mG = ec_mul(G, m)
    neg_mG = (mG[0], (-mG[1]) % p)
    gamma = A
    start2 = time.time()

    for i in range(m):
        xkey = 0 if gamma is None else int(gamma[0])
        if xkey in baby:
            j = baby[xkey]
            for n_cand in [i*m + j, i*m - j]:
                if 0 <= n_cand < (1 << 64):
                    if ec_mul(G, n_cand) == A:
                        print(f"FOUND n_a = {n_cand} (i={i}, j={j})", flush=True)
                        for by_cand in [by, p - by]:
                            B = (bx_pub, by_cand)
                            S = ec_mul(B, n_cand)
                            if S is None: continue
                            shared = int(S[0])
                            sha1 = hashlib.sha1()
                            sha1.update(str(shared).encode('ascii'))
                            key = sha1.digest()[:16]
                            cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex))
                            try:
                                flag = unpad(cipher.decrypt(bytes.fromhex(ct_hex)), 16)
                                print(f"Flag: {flag.decode()}", flush=True)
                                sys.exit(0)
                            except ValueError:
                                continue

        gamma = ec_add(gamma, neg_mG)
        if i > 0 and i % 10000000 == 0:
            elapsed = time.time() - start2
            rate = i / elapsed
            eta = (m - i) / rate
            print(f"  Giant {i}/{m} ({i*100//m}%), {rate:.0f} ops/s, ETA: {eta/3600:.1f}h", flush=True)

    print(f"No solution for this y", flush=True)

print("Failed!", flush=True)
