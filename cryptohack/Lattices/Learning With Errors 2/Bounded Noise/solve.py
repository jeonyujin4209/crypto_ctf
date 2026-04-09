"""
Bounded Noise: LWE with binary error e in {0, 1} mod q = 0x10001 = 65537 (prime).
A is m x n with m = n^2, n = 25. So we have m = 625 samples for a secret of
length 25. Standard Arora-Ge linearization works:

  (b_i - A_i . s)(b_i - A_i . s - 1) = 0  (mod q)

Expand in monomials { 1, s_j (j=0..n-1), s_j s_k (0<=j<=k<n) }.

That yields 625 linear equations in 1 + 25 + 325 = 351 unknowns -- overdetermined.
Solve over F_q and read off s_j from the linear monomials.
"""
import json, ast
import numpy as np
from Crypto.Util.number import long_to_bytes

q = 0x10001
assert q == 65537

with open("output.txt") as f:
    data = json.load(f)
A_raw = ast.literal_eval(data["A"])
b_raw = ast.literal_eval(data["b"])

m = len(A_raw)
n = len(A_raw[0])
print(f"m = {m}, n = {n}")

A = np.array(A_raw, dtype=np.int64)
b = np.array(b_raw, dtype=np.int64)

# Monomial ordering:
#   index 0: constant 1
#   index 1..n: s_0 .. s_{n-1}
#   index n+1..: s_j * s_k for 0 <= j <= k < n
pair_idx = {}
idx = 1 + n
for j in range(n):
    for k in range(j, n):
        pair_idx[(j, k)] = idx
        idx += 1
num_mono = idx
print(f"num_mono = {num_mono}")

# Build M (m x num_mono) and rhs v (m,) over F_q.
# The equation: L_i^2 - (2 b_i - 1) L_i + b_i (b_i - 1) = 0 (mod q)
# where L_i = sum_j A_ij s_j. So the coefficient of monomial s_j s_k (j<k) is
#   2 A_ij A_ik, and for s_j^2 it's A_ij^2.
# Plus coefficient of s_j is -(2 b_i - 1) A_ij, and constant term b_i (b_i - 1).
# We move constant to RHS: -b_i(b_i - 1).
M = np.zeros((m, num_mono - 1), dtype=np.int64)  # drop the constant column
rhs = np.zeros(m, dtype=np.int64)
for i in range(m):
    Ai = A[i] % q
    bi = int(b[i]) % q
    # Linear part
    lin_coeff = (-(2 * bi - 1)) % q
    for j in range(n):
        M[i, j] = (M[i, j] + lin_coeff * Ai[j]) % q
    # Quadratic part
    for j in range(n):
        for k in range(j, n):
            col = pair_idx[(j, k)] - 1  # shift since we dropped constant
            if j == k:
                coef = (Ai[j] * Ai[j]) % q
            else:
                coef = (2 * Ai[j] * Ai[k]) % q
            M[i, col] = (M[i, col] + coef) % q
    # RHS
    rhs[i] = (-bi * (bi - 1)) % q

# Now solve M x = rhs (mod q) where q is prime.
# Use Gaussian elimination over F_q.
def gf_solve(M, v, q):
    M = M.copy() % q
    v = v.copy() % q
    rows, cols = M.shape
    aug = np.hstack([M, v.reshape(-1, 1)]).astype(object)
    r = 0
    for c in range(cols):
        pivot = None
        for i in range(r, rows):
            if aug[i, c] % q != 0:
                pivot = i
                break
        if pivot is None:
            continue
        aug[[r, pivot]] = aug[[pivot, r]]
        inv = pow(int(aug[r, c]) % q, -1, q)
        aug[r] = (aug[r] * inv) % q
        for i in range(rows):
            if i != r and int(aug[i, c]) % q != 0:
                factor = int(aug[i, c]) % q
                aug[i] = (aug[i] - factor * aug[r]) % q
        r += 1
        if r == rows:
            break
    # Check consistency and extract
    x = np.zeros(cols, dtype=np.int64)
    # Read pivot rows
    row_of = [-1] * cols
    for i in range(rows):
        for c in range(cols):
            if int(aug[i, c]) % q == 1 and all(int(aug[i, cc]) % q == 0 for cc in range(c)):
                row_of[c] = i
                break
    for c in range(cols):
        if row_of[c] >= 0:
            x[c] = int(aug[row_of[c], cols]) % q
    return x

print("Solving linear system over F_q ...")
x = gf_solve(M, rhs, q)
# First n entries are s_0..s_{n-1}
s = x[:n]
print(f"s = {s.tolist()}")

# Reconstruct flag: flag_int = sum(s[i] * q^i)
flag_int = 0
for i, si in enumerate(s):
    flag_int += int(si) * (q ** i)
print(f"flag_int = {flag_int}")
flag = long_to_bytes(flag_int)
print(flag)
