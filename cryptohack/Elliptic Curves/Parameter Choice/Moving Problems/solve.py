"""Moving Problems - Using known order and CRT."""
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import gmpy2
from gmpy2 import mpz, invert
import math
from sympy.ntheory.modular import crt

p = mpz(1331169830894825846283645180581)
a = mpz(-35)
b = mpz(98)

Gx, Gy = mpz(479691812266187139164535778017), mpz(568535594075310466177352868412)
P1x, P1y = mpz(1110072782478160369250829345256), mpz(800079550745409318906383650948)
P2x, P2y = mpz(1290982289093010194550717223760), mpz(762857612860564354370535420319)

iv_hex = 'eac58c26203c04f68d63dc2c58d79aca'
ct_hex = 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'

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
P1 = (P1x, P1y)
P2 = (P2x, P2y)

# Pre-computed Pohlig-Hellman results (verified individually)
moduli = [2, 7, 271, 23687, 1153763334005213]
remainders = [1, 3, 54, 15933, 774386641791944]

# CRT: sympy returns (solution, modulus)
n_a, mod = crt(moduli, remainders)
print(f"n_a = {n_a} (mod {mod})", flush=True)

# Verify
check = ec_mul(G, int(n_a))
print(f"Verify n_a*G == P1: {check == P1}", flush=True)

if check != P1:
    print("Failed! Trying search...", flush=True)
    sys.exit(1)

# Decrypt: shared = (n_a * P2).x
S = ec_mul(P2, int(n_a))
shared = int(S[0])
sha1 = hashlib.sha1()
sha1.update(str(shared).encode('ascii'))
key = sha1.digest()[:16]
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)
cipher = AES.new(key, AES.MODE_CBC, iv)
try:
    flag = unpad(cipher.decrypt(ct), 16)
    print(f"Flag: {flag.decode()}", flush=True)
except ValueError:
    print("Wrong padding, trying -P2.y...", flush=True)
    S = ec_mul((P2x, (-P2y) % p), int(n_a))
    shared = int(S[0])
    sha1 = hashlib.sha1()
    sha1.update(str(shared).encode('ascii'))
    key = sha1.digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ct), 16)
    print(f"Flag: {flag.decode()}", flush=True)
