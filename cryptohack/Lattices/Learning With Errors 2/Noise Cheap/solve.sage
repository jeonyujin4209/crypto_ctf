#!/usr/bin/env sage
# Noise Cheap solver — Sage edition.
#
# Reads samples.json (produced by collect.py), runs LWE attack:
#   1. Multiply each sample by p^-1 mod q so the noise becomes ±1.
#   2. Build a primal "short-secret" lattice using the first n samples
#      to express S in terms of e_0 ∈ {-1,0,1}^n, then write the next
#      m extra constraints as y_i = e_i - W_i e_0  (mod q).
#   3. Embed (n+m+1)-dim lattice with target vector → BKZ → CVP via
#      Babai. Extract e_0 → recover S → decrypt flag.
#
# Save flag to flag.txt for the wrapper to read.

import json

n = 64
p = 257
q = 1048583

print("[*] loading samples.json")
with open("samples.json") as fh:
    data = json.load(fh)
samples = data["samples"]
flag_cts = data["flag_cts"]
print(f"    {len(samples)} samples, {len(flag_cts)} flag bytes")

Fq = GF(q)
p_inv = Fq(p)^(-1)

# Scale: c_i = b_i / p, A'_i = A_i / p  →  c_i ≡ A'_i · S + e_i (mod q),  e_i ∈ {-1,0,1}
A_scaled = [[Fq(a) * p_inv for a in s["A"]] for s in samples]
c_scaled = [Fq(s["b"]) * p_inv for s in samples]

# First n form A_0; assume invertible, retry pivot if not
A0 = matrix(Fq, A_scaled[:n])
while not A0.is_invertible():
    print("[!] first n samples singular — shouldn't happen with random samples")
    raise SystemExit(1)
A0_inv = A0.inverse()
b0 = vector(Fq, c_scaled[:n])

m = len(samples) - n
W_rows = []
y_vals = []
for i in range(n, n + m):
    Ai = vector(Fq, A_scaled[i])
    w = A0_inv.transpose() * Ai          # column-wise relation
    y_i = c_scaled[i] - w.dot_product(b0)
    W_rows.append([int(x) for x in w])
    y_vals.append(int(y_i))

W = matrix(ZZ, W_rows)                   # m x n

# Build embedding lattice basis (n + m + 1) x (n + m + 1):
#   [ I_n     -W^T          0 ]   row k=0..n-1   (variable e_0)
#   [ 0       q*I_m         0 ]   row k=n..n+m-1 (modulus rows)
#   [ 0       y_vec         1 ]   target row (embedding constant K)
#
# Short vector: (e_0, e_new, K) with all coords in {-1,0,1,K}, K ~ 1.

K = 1   # embedding constant (small since e ∈ {-1,0,1})
B = matrix(ZZ, n + m + 1, n + m + 1)
# Rows 0..n-1: (e_j, W^T[j, *]) — gives lattice element (a, W a) for a=e_0
for j in range(n):
    B[j, j] = 1
    for i in range(m):
        B[j, n + i] = W[i, j] % q
# Rows n..n+m-1: q-multiples in the "constraint" coordinates
for i in range(m):
    B[n + i, n + i] = q
# Last row (Kannan target embed): B[n+m, *] = (target, K). Kannan finds the
# lattice point closest to -target. We want lattice pt ≈ (0, -y), so
# target = -(0, -y) = (0, +y).
for i in range(m):
    B[n + m, n + i] = y_vals[i] % q
B[n + m, n + m] = K

print(f"[*] BKZ on {B.nrows()}x{B.ncols()} lattice (block_size=20)")
B_red = B.BKZ(block_size=20)
print("[*] BKZ done")

# Find the row whose last entry equals ±K — that's the embedded target
e0 = None
for row in B_red.rows():
    if abs(row[-1]) != K:
        continue
    sign = 1 if row[-1] == K else -1
    cand = [sign * int(row[j]) for j in range(n)]
    if all(v in (-1, 0, 1) for v in cand):
        e0 = cand
        break

if e0 is None:
    print("[!] no candidate row found; trying all short rows")
    for row in B_red.rows()[:5]:
        print("   ", row[:5], "...", row[-3:])
    raise SystemExit(1)

print(f"[+] e_0 head: {e0[:10]}")

c0 = vector(Fq, c_scaled[:n])
e0_vec = vector(Fq, e0)
S = A0_inv * (c0 - e0_vec)
print(f"[+] S head: {[int(x) for x in S[:5]]}")

# Verify against all collected samples
bad = 0
for s in samples:
    A = vector(Fq, s["A"])
    b = Fq(s["b"])
    d = int(b - A.dot_product(S))
    if d > q // 2:
        d -= q
    if d not in (-p, 0, p):
        bad += 1
print(f"[*] verification: {bad}/{len(samples)} bad")
if bad > 0:
    raise SystemExit("S verification failed")

# Decrypt flag
flag_bytes = []
for fc in flag_cts:
    A = vector(Fq, fc["A"])
    b = Fq(fc["b"])
    d = int(b - A.dot_product(S))
    if d > q // 2:
        d -= q
    m_byte = d % p
    flag_bytes.append(m_byte)

flag = bytes(flag_bytes)
print(f"FLAG: {flag.decode(errors='replace')}")
with open("flag.txt", "w") as fh:
    fh.write(flag.decode(errors="replace") + "\n")
