"""
GLP420 (HackTM CTF 2023) - Forgery via cyclotomic factorization

Vulnerability:
  GLP signature variant uses ring R_q = F_q[x]/(x^420 - 1). The polynomial
  x^420 - 1 = prod_{d | 420} Phi_d(x) is REDUCIBLE (instead of x^n + 1 with
  n a power of 2 in the irreducible cyclotomic case). So R_q decomposes via
  CRT into 24 smaller rings R_q_d = F_q[x]/Phi_d(x) for each divisor d of 420.

  Critical: the secret s, e (binary {-1, 0, 1} polynomials) project to small
  Z-coefficient polynomials in each R_q_d (max coefficient ~30 even for the
  largest factor Phi_420 of degree 96). Thus, for each d, we can recover
  (s mod Phi_d), (e mod Phi_d) via a small lattice attack of dim 2*phi(d) + 1
  (max phi(d) = 96, giving dim 193 — easy LLL).

Attack:
  1. Connect to server, parse public a, t.
  2. For each d | 420, reduce a, t mod Phi_d, run lattice attack to recover
     (s mod Phi_d), (e mod Phi_d) as small Z-coef polynomials.
  3. Combine via Q-polynomial CRT to recover s, e in Z[x] (ternary coefs).
  4. Sign the message normally (Lyubashevsky-style with rejection sampling).
  5. Submit forged signature.
"""

import sys
import os
import socket
import time
from random import SystemRandom
from hashlib import sha256
from fpylll import IntegerMatrix, LLL

# pycryptodome
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Parameters
q = 8383489
b = 16383
w = 3
n = 420

# ---- Connect, fetch a, t ----
HOST = "archive.cryptohack.org"
PORT = int(26931)

def recvuntil(s, marker):
    data = b""
    while marker not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    return data

print("Connecting...", flush=True)
sock = socket.create_connection((HOST, PORT), timeout=30)
sock.settimeout(30)
data = recvuntil(sock, b"z1 = ")
print(f"Got {len(data)} bytes from server", flush=True)
text = data.decode()
# Parse a_enc, t_enc
import re
m_a = re.search(r"a_enc\s*=\s*([0-9a-f]+)", text)
m_t = re.search(r"t_enc\s*=\s*([0-9a-f]+)", text)
assert m_a and m_t, "Couldn't parse a/t from server"
a_enc = bytes.fromhex(m_a.group(1))
t_enc = bytes.fromhex(m_t.group(1))
assert len(a_enc) == 3 * n
assert len(t_enc) == 3 * n

a_coefs = [bytes_to_long(a_enc[3*i:3*(i+1)]) % q for i in range(n)]
t_coefs = [bytes_to_long(t_enc[3*i:3*(i+1)]) % q for i in range(n)]
print(f"Parsed a, t. a[0]={a_coefs[0]}, t[0]={t_coefs[0]}", flush=True)

# ---- Run lattice attack ----
PR.<x> = PolynomialRing(ZZ)
PRq = PolynomialRing(GF(q), 'xq')
xq = PRq.gen()

a_poly_zz = sum(a_coefs[i] * x**i for i in range(n))
t_poly_zz = sum(t_coefs[i] * x**i for i in range(n))

def divisors(N):
    return [d for d in range(int(1), int(N)+int(1)) if N % d == 0]

recovered = {}

t_start = time.time()
for d in divisors(n):
    phi_d = cyclotomic_polynomial(d)
    deg_phi = phi_d.degree()

    # a_d = a mod Phi_d, t_d = t mod Phi_d (in Z[x]/Phi_d, then reduce coefs mod q)
    a_d_zz = a_poly_zz % phi_d
    t_d_zz = t_poly_zz % phi_d

    if deg_phi == 1:
        # Linear case: Phi_d = x - alpha
        roots = phi_d.roots(GF(q))
        alpha = int(roots[int(0)][int(0)])
        a_at = sum(a_coefs[i] * pow(alpha, int(i), q) for i in range(n)) % q
        t_at = sum(t_coefs[i] * pow(alpha, int(i), q) for i in range(n)) % q
        Nbound = n
        cands = []
        for s_at_cand in range(int(-Nbound), int(Nbound)+int(1)):
            e_at_cand = (t_at - a_at * s_at_cand) % q
            if e_at_cand > q // 2:
                e_at_cand -= q
            if abs(int(e_at_cand)) <= Nbound:
                cands.append((s_at_cand, e_at_cand))
        assert len(cands) == 1, f"d={d}: ambiguous candidates: {len(cands)}"
        s_at, e_at = cands[int(0)]
        recovered[d] = (PR(int(s_at)), PR(int(e_at)))
        print(f"d={d}: linear ok, s={s_at}, e={e_at}", flush=True)
    else:
        # Build matrix for multiplication by a_d in F_q[x]/Phi_d
        a_d_q = PRq([int(c) for c in a_d_zz.list()])
        phi_d_q = PRq([int(c) for c in phi_d.list()])
        t_d_q = PRq([int(c) for c in t_d_zz.list()])

        Ma = [[int(0)] * deg_phi for _ in range(deg_phi)]
        for j in range(deg_phi):
            poly = (a_d_q * xq**j) % phi_d_q
            for i in range(deg_phi):
                Ma[i][j] = int(poly[i])
        t_d_vec = [int(t_d_q[i]) for i in range(deg_phi)]

        # Lattice basis: dim 2*deg_phi + 1
        D = int(2) * int(deg_phi) + int(1)
        B = IntegerMatrix(D, D)
        for j in range(deg_phi):
            B[j, j] = int(1)
            for k in range(deg_phi):
                B[j, deg_phi + k] = int(-Ma[k][j])
        for j in range(deg_phi):
            B[deg_phi + j, deg_phi + j] = int(q)
        for k in range(deg_phi):
            B[2 * deg_phi, deg_phi + k] = int(t_d_vec[k])
        B[2 * deg_phi, 2 * deg_phi] = int(1)

        LLL.reduction(B)

        # Find row with last coord = ±1 satisfying LWE
        found = False
        for i in range(D):
            v = [B[i, jj] for jj in range(D)]
            last = v[2 * deg_phi]
            if abs(last) == 1:
                sign = -1 if last < 0 else 1
                s_part = [sign * v[jj] for jj in range(deg_phi)]
                e_part = [sign * v[deg_phi + jj] for jj in range(deg_phi)]
                # Verify LWE
                ok = True
                for k in range(deg_phi):
                    val = sum(Ma[k][j] * s_part[j] for j in range(deg_phi)) + e_part[k]
                    if (val - t_d_vec[k]) % q != 0:
                        ok = False
                        break
                if ok:
                    recovered[d] = (PR(s_part), PR(e_part))
                    sn = sum(c*c for c in s_part)**0.5
                    en = sum(c*c for c in e_part)**0.5
                    print(f"d={d}: deg={deg_phi}, ||s||={sn:.1f}, ||e||={en:.1f}", flush=True)
                    found = True
                    break
        if not found:
            raise RuntimeError(f"d={d}: lattice attack failed!")

print(f"All recovered in {time.time()-t_start:.1f}s", flush=True)

# CRT-combine
PRQ = PolynomialRing(QQ, 'x')
xQ = PRQ.gen()
moduli = [PRQ(cyclotomic_polynomial(d)) for d in divisors(n)]
s_d_list = [PRQ(recovered[d][int(0)]) for d in divisors(n)]
e_d_list = [PRQ(recovered[d][int(1)]) for d in divisors(n)]

s_recovered = CRT_list(s_d_list, moduli)
e_recovered = CRT_list(e_d_list, moduli)

# Should have integer coefficients in {-1, 0, 1}
s_list = [int(round(c)) for c in s_recovered.list()]
e_list = [int(round(c)) for c in e_recovered.list()]

# Pad to length n
while len(s_list) < n:
    s_list.append(int(0))
while len(e_list) < n:
    e_list.append(int(0))

print(f"s in [-1,1]? {all(abs(c) <= 1 for c in s_list)}", flush=True)
print(f"e in [-1,1]? {all(abs(c) <= 1 for c in e_list)}", flush=True)

# Verify a*s + e == t mod (q, x^n - 1)
prod_zz = sum(a_coefs[i] * s_list[j] * x**(i+j) for i in range(n) for j in range(n))
# Wait, for n=420 this is n^2 = 176400 monomials, takes time. Let me use a different approach.
# Actually, just do mult in PR and reduce.

# Compute (a * s) mod (x^n - 1) mod q
s_poly = PR(s_list)
a_poly = PR(a_coefs)
e_poly = PR(e_list)
t_poly = PR(t_coefs)

prod = (a_poly * s_poly) % (x**n - int(1))
check_lhs = prod + e_poly
check_diff = check_lhs - t_poly
all_zero = all(int(c) % q == int(0) for c in check_diff.list())
print(f"a*s + e == t mod (q, x^n - 1)? {all_zero}", flush=True)

assert all_zero, "Recovery failed!"

# ---- Sign the message ----
m_msg = b"sign me!"

# Build Rq for actual signing
PRRq = PolynomialRing(GF(q), 'xrq')
xrq = PRRq.gen()
Rq = PRRq.quotient(xrq**n - int(1), 'xrq')

a_rq = Rq([a_coefs[i] for i in range(n)])
t_rq = Rq([t_coefs[i] for i in range(n)])
s_rq = Rq([s_list[i] for i in range(n)])
e_rq = Rq([e_list[i] for i in range(n)])

# Verify in Rq
assert a_rq * s_rq + e_rq == t_rq, "Rq verify fail"
print("Rq verify OK", flush=True)

def polyhash(poly, m_bytes):
    h = sha256()
    for i in range(n):
        h.update(long_to_bytes(int(poly[i]), int(3)))
    h.update(m_bytes)
    return h.digest()

def hash2poly(h):
    hash_int = bytes_to_long(h)
    coefs = [int(int(int(int(int(1)) << int(i)) & int(hash_int)) != int(0)) for i in range(n)]
    return Rq(coefs)

def encode_poly(poly):
    enc = b""
    for i in range(n):
        enc += long_to_bytes(int(poly[i]), int(3))
    return enc

def sample_poly(K, rnd):
    coefs = [int(rnd.randint(-K, K)) for _ in range(n)]
    return Rq(coefs)

def sign(m_bytes, s_rq, e_rq, t_rq, a_rq, rnd):
    while True:
        y1 = sample_poly(b, rnd)
        y2 = sample_poly(b, rnd)
        c_ = polyhash(a_rq * y1 + y2, m_bytes)
        c = hash2poly(c_)
        z1 = s_rq * c + y1
        z2 = e_rq * c + y2
        valid = True
        for i in range(n):
            z1i = int(z1[i])
            z2i = int(z2[i])
            if b - w < z1i < q - (b - w) or b - w < z2i < q - (b - w):
                valid = False
                break
        if valid:
            return z1, z2, c

print("Signing...", flush=True)
rnd = SystemRandom()
z1, z2, c = sign(m_msg, s_rq, e_rq, t_rq, a_rq, rnd)
print("Signed.", flush=True)

# Verify locally
def verify(m_bytes, sig, t_rq, a_rq):
    z1, z2, c = sig
    for i in range(n):
        if min(int(z1[i]), q - int(z1[i])) > b - w:
            return False
        if min(int(z2[i]), q - int(z2[i])) > b - w:
            return False
    d_ = polyhash(a_rq * z1 + z2 - t_rq * c, m_bytes)
    d = hash2poly(d_)
    return d == c

assert verify(m_msg, (z1, z2, c), t_rq, a_rq), "Local verify fail"
print("Local verify OK", flush=True)

# Submit
z1_enc = encode_poly(z1)
z2_enc = encode_poly(z2)
c_enc = encode_poly(c)
print(f"Sending z1 ({len(z1_enc)} bytes)...", flush=True)
sock.sendall(z1_enc.hex().encode() + b"\n")
data = recvuntil(sock, b"z2 = ")
sock.sendall(z2_enc.hex().encode() + b"\n")
data = recvuntil(sock, b"c = ")
sock.sendall(c_enc.hex().encode() + b"\n")
sock.settimeout(int(10))
try:
    final = b""
    while True:
        chunk = sock.recv(int(65536))
        if not chunk:
            break
        final += chunk
except socket.timeout:
    pass
print("---SERVER RESPONSE---")
print(final.decode(errors='replace'))
sock.close()
