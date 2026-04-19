"""
Functional (ICC Athens 2022) solver.

Setup
-----
F = GF(2^142 - 111). Three intermixed linear recurrences f, g, h, i (with affine
polynomial-in-n perturbations), plus a sparse order-10000 recurrence j.

Stage 1 prints 500 values: [f(ITERS+k) for k in 0..499] where ITERS = randrange(13^37) ~ 2^137.
Stage 3 encrypts flag with AES-ECB, key = sha256(str(j(ITERS))).

Attack
------
1. Berlekamp-Massey on stage1 → char poly P_f of order L=20.
   Factors: q1(2) * q2(2) * (x^3 + 31337)^3 * q4(7).
   The REPEATED factor (x^3+31337)^3 gives a nilpotent/Jordan block — exploit it.

2. Recover ITERS without DLP via the polynomial-in-n formula:
   N := x^3 + 31337, x^n = x^r * [(-31337)^m + m(-31337)^{m-1} N + C(m,2)(-31337)^{m-2} N^2]
   where n = 3m + r, r ∈ {0,1,2}. Project states onto the 9-dim (x^3+31337)^3
   subspace via CRT projector, express in cyclic basis from initial state, read off
   coefficients, solve m = -31337 * B / A (field element == integer since m < p).

3. Compute S3 = [i(ITERS+k) for k in 0..1336] via 17x17 matrix exponentiation on
   joint (g, h, i) state augmented with (1, n, n^2, n^3) affine term.

4. Compute j(ITERS) via Kitamasa on sparse order-L=10000 recurrence
   (note L=10000, not 9999: the recurrence applies only for n ≥ 10^4 since
    n < 10^4 is the base case — off-by-one trap).
   Base: j(k) = Σ S3[d] for d in digits of k base 1337, for k = 0..9999.
   Result: j(ITERS) = Σ_{k<10000} r_k * j(k) where r(X) = X^ITERS mod P_j(X).

5. Derive key = sha256(str(j(ITERS))), AES-ECB decrypt ciphertext.
"""
import re, numpy as np
from time import time

p = 2^142 - 111
F = GF(p)
Fx.<X> = F[]

# --- Parse output ---
with open('output.txt') as f:
    data = f.read()
stage1 = [F(int(v)) for v in re.search(r'\[(\d[^\]]*)\]', data).group(1).split(',')]
print(f"stage1: {len(stage1)} values")

# --- BM → recurrence for f ---
from sage.matrix.berlekamp_massey import berlekamp_massey
Pf = Fx(berlekamp_massey(stage1))
L = Pf.degree()
print(f"L = {L}")
fac = Pf.factor()
target = X^3 + F(31337)
# Check that target^3 divides Pf
assert Pf % target^3 == 0 and (Pf // target^3) % target != 0, "(x^3+31337)^3 not a factor"

# --- Recover ITERS via Jordan projection ---
s0_f = vector(F, [F(int(10000 * np.sin(float(n)))) for n in range(L)])
s_iters_f = vector(F, stage1[:L])

# Companion matrix M for f
M = matrix(F, L, L, 0)
for i in range(L-1): M[i, i+1] = 1
cs = [-Pf[L-1-k] for k in range(L)]
for j in range(L): M[L-1, j] = cs[L-1-j]

# CRT projector onto V_3 = ker((M^3 + 31337)^3) generalized eigenspace
Q = Pf // target^3
g, a, b = xgcd(target^3, Q)
assert g == 1
R_proj = b * Q       # R ≡ 1 mod target^3 and R ≡ 0 mod Q

def apply_poly(poly, v):
    coefs = poly.coefficients(sparse=False)
    acc = vector(F, [0]*L); mkv = v
    for k, c in enumerate(coefs):
        if c != 0: acc += c * mkv
        if k < len(coefs) - 1: mkv = M * mkv
    return acc

s0_v3 = apply_poly(R_proj, s0_f)
sN_v3 = apply_poly(R_proj, s_iters_f)

# Cyclic basis {M^k s0_v3}_{k=0..8}, solve for coefs of x^n mod (x^3+31337)^3
cyc = []; cur = s0_v3
for _ in range(9):
    cyc.append(cur); cur = M * cur
c = matrix(F, cyc).transpose().solve_right(sN_v3)

nz = [k for k in range(9) if c[k] != 0]
# Expand x^r * [(A+31337B+31337^2 C) + (B+2*31337 C) x^3 + C x^6] in basis 1..x^8
# Nonzero positions {r, r+3, r+6}.
r_val = min(nz)
assert set(nz) == {r_val, r_val+3, r_val+6}
A_prime, B_prime, C_prime = c[r_val], c[r_val+3], c[r_val+6]
K = F(31337)
C_coef = C_prime
B_coef = B_prime - 2*K*C_coef
A_coef = A_prime - K*B_coef - K^2*C_coef
# A = (-K)^m, B = m*A/(-K), so m = -K*B/A in F_p; since m < p, m_int = int(m)
m_int = int(-K * B_coef / A_coef)
assert (F(m_int) * F(m_int - 1) / 2 * A_coef / K^2) == C_coef, "C mismatch"
assert (-K)^m_int == A_coef, "u mismatch"
ITERS = 3 * m_int + r_val
print(f"ITERS = {ITERS} (bits={ITERS.nbits()})")
assert ITERS < 13^37

# Verify against all 500 stage1 values
cur_pow = power_mod(X, ITERS, Pf)
matches = 0
for i in range(len(stage1)):
    fi = sum(cur_pow[k] * s0_f[k] for k in range(L))
    if fi == stage1[i]: matches += 1
    cur_pow = (cur_pow * X) % Pf
print(f"stage1 verify: {matches}/{len(stage1)}")
assert matches == len(stage1)

# --- Compute S3 = [i(ITERS+k) for k in 0..1336] via 17-dim joint (g,h,i) state ---
alpha_g = [F(int(10000 * np.log10(float(2 + k)))) for k in range(6)]
alpha_h = [F(int(10000 * np.log10(float(1337 + k)))) for k in range(4)]
alpha_i = [F(int(10000 * np.log10(float(31337 + k)))) for k in range(5)]

g_base = [F(int(10000 * np.sin(float(L + n)))) for n in range(6)]
h_base = [F(int(10000 * np.sin(float(L + 6 + n)))) for n in range(3)]
i_base = [F(int(10000 * np.sin(float(L + 9 + n)))) for n in range(3)]

def compute_ghi_naive(N):
    G, H, I = list(g_base), list(h_base), list(i_base)
    for n in range(3, N+1):
        hn = alpha_h[0]*H[n-3] + alpha_h[1]*I[n-1] + alpha_h[2]*G[n-2] + alpha_h[3]*H[n-1] + F(n)
        in_ = alpha_i[0]*I[n-2] + alpha_i[1]*G[n-3] + alpha_i[2]*H[n-3] + alpha_i[3]*H[n-1] + alpha_i[4]*I[n-1] + F(1)
        H.append(hn); I.append(in_)
        if n >= 6:
            gn = alpha_g[0]*G[n-6] + alpha_g[1]*H[n-2] + alpha_g[2]*I[n-3] + alpha_g[3]*G[n-3] + alpha_g[4]*H[n-4] + alpha_g[5]*I[n] + F(2*n^3 + 42)
            G.append(gn)
    return G, H, I

n_start = 10
G, H, I = compute_ghi_naive(n_start)

# State layout: [g(n-5..n), h(n-3..n), i(n-2..n), 1, n, n^2, n^3]
def mkstate(n, G, H, I):
    return vector(F, [G[n-5], G[n-4], G[n-3], G[n-2], G[n-1], G[n],
                      H[n-3], H[n-2], H[n-1], H[n],
                      I[n-2], I[n-1], I[n], F(1), F(n), F(n)^2, F(n)^3])

M_gh = matrix(F, 17, 17, 0)
# Shifts
for k in range(5): M_gh[k, k+1] = 1
for k in range(3): M_gh[6+k, 6+k+1] = 1
for k in range(2): M_gh[10+k, 10+k+1] = 1
# h(n+1)
M_gh[9, 7] = alpha_h[0]; M_gh[9, 12] = alpha_h[1]; M_gh[9, 4] = alpha_h[2]
M_gh[9, 9] = alpha_h[3]; M_gh[9, 14] = F(1); M_gh[9, 13] = F(1)
# i(n+1)
M_gh[12, 11] = alpha_i[0]; M_gh[12, 3] = alpha_i[1]; M_gh[12, 7] = alpha_i[2]
M_gh[12, 9] = alpha_i[3]; M_gh[12, 12] = alpha_i[4]; M_gh[12, 13] = F(1)
# g(n+1)
M_gh[5, 0] = alpha_g[0]; M_gh[5, 8] = alpha_g[1]; M_gh[5, 10] = alpha_g[2]
M_gh[5, 3] = alpha_g[3]; M_gh[5, 6] = alpha_g[4]
M_gh[5, 11] += alpha_g[5] * alpha_i[0]; M_gh[5, 3] += alpha_g[5] * alpha_i[1]
M_gh[5, 7]  += alpha_g[5] * alpha_i[2]; M_gh[5, 9] += alpha_g[5] * alpha_i[3]
M_gh[5, 12] += alpha_g[5] * alpha_i[4]; M_gh[5, 13] += alpha_g[5]
M_gh[5, 16] += F(2); M_gh[5, 15] += F(6); M_gh[5, 14] += F(6); M_gh[5, 13] += F(44)
# Affine
M_gh[13, 13] = 1
M_gh[14, 14] = 1; M_gh[14, 13] = 1
M_gh[15, 15] = 1; M_gh[15, 14] = 2; M_gh[15, 13] = 1
M_gh[16, 16] = 1; M_gh[16, 15] = 3; M_gh[16, 14] = 3; M_gh[16, 13] = 1

# Sanity
assert M_gh * mkstate(n_start, G, H, I) == mkstate(n_start+1, *compute_ghi_naive(n_start+1))

t0 = time()
state_iters = (M_gh^(ITERS - n_start)) * mkstate(n_start, G, H, I)
print(f"matrix exp in {time()-t0:.1f}s")

S3 = []
st = state_iters
for _ in range(1337):
    S3.append(st[12])
    st = M_gh * st

# --- Compute j(ITERS) via Kitamasa, L = 10000 (critical!) ---
alpha_j = [F(int(10000 * np.log(float(31337 + k)))) for k in range(100)]
# P_j(X) = X^10000 - Σ α_i X^{100-i}
coef = {10000: F(1)}
for i in range(100): coef[100 - i] = -alpha_j[i]
Pj = Fx(coef)

t0 = time()
r_poly = power_mod(X, ITERS, Pj)
print(f"X^ITERS mod Pj in {time()-t0:.1f}s")

# Base j values for k = 0..9999
j_vals = [sum((S3[d] for d in ZZ(k).digits(1337)), F(0)) for k in range(10000)]
j_iters = sum((r_poly[k] * j_vals[k] for k in range(10000) if r_poly[k] != 0), F(0))
print(f"j(ITERS) = {j_iters}")

# Write j(ITERS) for the Python decrypt wrapper.
with open('j_iters.txt', 'w') as fout:
    fout.write(str(j_iters))
print(f"RESULT: j_iters = {j_iters}")
