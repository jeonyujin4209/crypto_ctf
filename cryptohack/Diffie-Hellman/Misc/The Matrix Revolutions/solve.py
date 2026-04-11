"""
The Matrix Revolutions — full solver

Setup: Matrix DH over GF(2) with N = 150 and 149-bit prime exponents.
Min poly of G factors over GF(2) as f_61(x) * f_89(x) (two distinct
irreducibles). Therefore the matrix DLP G^A_priv = A_pub reduces, by CRT
on the polynomial ring, to two extension-field DLPs:

    α^A_priv = c_A(α)   in  GF(2^61) = GF(2)[x]/f_61
    β^A_priv = c_A(β)   in  GF(2^89) = GF(2)[x]/f_89

Both 2^61-1 and 2^89-1 are Mersenne primes, so Pohlig-Hellman doesn't help.
A pure-Python Pollard rho on 2^89-1 is infeasible (~2^45 mults). We solve
both DLPs by shelling out to PARI/GP's `fflog`, which uses Coppersmith /
function-field-sieve and finishes in seconds for these sizes. Then CRT
gives A_priv exactly (since (2^61-1)(2^89-1) > 2^149 ≥ A_priv).

With A_priv in hand, the shared secret matrix is B_pub^A_priv, and the AES
key is sha256 of its bit-string representation.

Steps:
  1. Read G, A_pub, B_pub, flag.enc.
  2. Compute the minimal polynomial of G via Krylov + Berlekamp-Massey.
  3. Factor min_poly over GF(2) → degree-61 and degree-89 irreducibles.
  4. For A_pub, compute the polynomial c_A(x) of degree < 150 such that
     A_pub · v = c_A(G) · v for our generic v (Krylov solve over GF(2)).
  5. Write input.gp with f61, f89, A_poly, B_poly. Invoke PARI/GP via
     `gp -q dlp.gp` to compute A_priv.
  6. Verify G^A_priv == A_pub, then compute shared = B_pub^A_priv,
     derive the AES key, and decrypt the flag.

Requires:
  - galois (for fast GF(2) matrix arithmetic and minimal polynomial)
  - PARI/GP at /tmp/pari/gp.exe
"""
import json
import os
import pickle
import subprocess
from hashlib import sha256

import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import galois

# PARI/GP binary (downloaded from pari.math.u-bordeaux.fr)
GP = os.environ.get("GP_EXE", os.path.expanduser(r"~/AppData/Local/Temp/pari/gp.exe"))

n = 150
GF2 = galois.GF(2)


def read_matrix(fname):
    lines = open(fname).read().strip().split("\n")
    return GF2([[int(c) for c in line] for line in lines])


print("[1] Reading inputs...")
G = read_matrix("generator.txt")
A_pub = read_matrix("alice.pub")
B_pub = read_matrix("bob.pub")
with open("flag.enc") as f:
    flag_data = json.load(f)


def bm(s):
    """Berlekamp-Massey over GF(2): returns (L, C) where C is the LFSR
    feedback polynomial and L is its degree (i.e. the linear complexity
    of the sequence)."""
    nn = len(s)
    C, B = [1], [1]
    L, m = 0, 1
    for i in range(nn):
        d = s[i]
        for j in range(1, len(C)):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            shift = [0] * m + B
            while len(shift) < len(C):
                shift.append(0)
            while len(C) < len(shift):
                C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            L, B, m = i + 1 - L, T, 1
        else:
            shift = [0] * m + B
            while len(shift) < len(C):
                shift.append(0)
            while len(C) < len(shift):
                C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            m += 1
    return L, C


print("[2] Computing minimal polynomial via Krylov + BM...")
np.random.seed(42)
v0 = GF2(np.random.randint(0, 2, size=n).astype(np.int8))
seq = []
cur = v0
for _ in range(2 * n + 5):
    seq.append(int(cur[0]))
    cur = G @ cur
L, mp_coeffs = bm(seq)
assert L == n, f"min poly degree = {L} != {n}; vector wasn't generic"
# BM convention: mp_coeffs = [1, c_1, c_2, ..., c_L] is the connection
# polynomial (s_i = sum_{j>=1} c_j s_{i-j}). The corresponding min poly,
# in HIGH-to-LOW coefficient order (which galois.Poly expects), is the
# raw mp_coeffs list itself (not reversed): the polynomial is
# x^L + c_1 x^(L-1) + ... + c_L.
mp = galois.Poly(mp_coeffs, field=GF2)
print(f"    min poly degree = {mp.degree}")
# Sanity check: min poly really annihilates G as a matrix (verified by
# evaluating on a generic vector — cheaper than the full matrix product).
_check = GF2(np.zeros(n, dtype=np.int8))
_pv = v0
for _i in range(L + 1):
    if mp_coeffs[L - _i]:  # ascending: coef of x^_i
        _check += _pv
    _pv = G @ _pv
assert not _check.any(), "BM-derived min poly does not annihilate G"

print("[3] Factoring min poly over GF(2)...")
factors_data = mp.factors()
factors_with_mult = list(zip(*factors_data))
print(f"    {len(factors_with_mult)} factors:")
for f, m_ in factors_with_mult:
    print(f"      degree {f.degree}, mult {m_}")
f_61 = next(f for f, _ in factors_with_mult if f.degree == 61)
f_89 = next(f for f, _ in factors_with_mult if f.degree == 89)


def krylov_solve(M_pub, v, K_mat):
    """Express M_pub as a polynomial in G applied to v, returning the
    coefficient vector c (low-to-high) such that M_pub·v = c(G)·v."""
    target = M_pub @ v
    sol = np.linalg.solve(K_mat, target)  # galois override → GF(2) solve
    return [int(x) for x in np.array(sol)]


# Build Krylov basis once and reuse
K_basis = []
_cur = v0
for _ in range(n):
    K_basis.append(_cur)
    _cur = G @ _cur
K_mat = GF2(np.column_stack([np.array(k) for k in K_basis]))


print("[4] Reducing A_pub and B_pub to polynomial form...")
A_poly = krylov_solve(A_pub, v0, K_mat)
B_poly = krylov_solve(B_pub, v0, K_mat)


def coeffs_to_pari(coeffs, var):
    terms = []
    for i, c in enumerate(coeffs):
        if int(c):
            if i == 0:
                terms.append("1")
            elif i == 1:
                terms.append(var)
            else:
                terms.append(f"{var}^{i}")
    return " + ".join(terms) if terms else "0"


print("[5] Writing PARI input and invoking gp...")
with open("input.gp", "w") as fh:
    fh.write(f"f61 = {coeffs_to_pari([int(c) for c in f_61.coefficients(order='asc')], 't')};\n")
    fh.write(f"f89 = {coeffs_to_pari([int(c) for c in f_89.coefficients(order='asc')], 't')};\n")
    fh.write(f"A_poly = {coeffs_to_pari(A_poly, 'x')};\n")
    fh.write(f"B_poly = {coeffs_to_pari(B_poly, 'x')};\n")

result = subprocess.run([GP, "-q", "dlp.gp"], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print("PARI stderr:", result.stderr)
    raise RuntimeError("PARI failed")

A_priv = int(open("output.txt").read().strip())
print(f"[6] A_priv = {A_priv} ({A_priv.bit_length()} bits)")


def matpow_gf2(M, e):
    result = GF2(np.eye(n, dtype=np.int8))
    base = M
    while e > 0:
        if e & 1:
            result = result @ base
        base = base @ base
        e >>= 1
    return result


print("[7] Verifying G^A_priv == A_pub...")
test = matpow_gf2(G, A_priv)
assert np.array_equal(np.array(test), np.array(A_pub)), "verification failed"
print("    [OK] verified")

print("[8] Computing shared = B_pub^A_priv...")
shared = matpow_gf2(B_pub, A_priv)

mat_str = "".join(str(int(x)) for row in np.array(shared) for x in row)
key = sha256(mat_str.encode()).digest()[:32]  # KEY_LENGTH=128 (in source) but sha256 → 32B
iv = bytes.fromhex(flag_data["iv"])
ct = bytes.fromhex(flag_data["ciphertext"])
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print()
print("FLAG:", pt.decode())
