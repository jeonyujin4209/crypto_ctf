---
name: hyperelliptic-jacobian-mumford-leak
description: Hyperelliptic Jacobian PRNG/encryption that exposes full Mumford coords (u,v) leaks the curve poly f via v^2 ≡ f mod u (linear system), and the divisor itself if v is fully known (factor v^2-f).
type: attack
---

# Hyperelliptic Jacobian Mumford-coordinate leak

## When to use

Challenge defines `J = HyperellipticCurve(f, 0).jacobian()` and outputs full Mumford-form
coordinates of points P in J — typically `[u[i] for i in range(g)] + [v[i] for i in range(g)]`
(2g coefficients, each in GF(p)). f may be SECRET (random) and the point unknown.

## Key facts

In Mumford rep, divisor (u, v) on the Jacobian satisfies:
- u monic, deg u ≤ g (generically = g)
- deg v < deg u
- **v(x)^2 ≡ f(x) (mod u(x))** — fundamental Mumford constraint

This is 7 equations of degree ≤ 6 in coefficients of v² - f mod u.

## Step 1 — Recover unknown f via linear algebra

For each leaked (u, v) pair:
- Compute `(v*v) % u` → 7 known values (deg < g coefficients)
- Compute `x^i mod u` for i = 0..2g-1 (deg f range) → linear combinations of f's coefficients
- Equation: `Σ_i f_i · (x^i mod u)[j] = (v² mod u)[j]` for j = 0..g-1

Each query yields g linear equations on 2g+2 (or however many) coefficients of f. With ⌈(2g+2)/g⌉
queries you over-determine f. For g=7 with deg(f)=15 (16 unknowns), 3 queries (21 eqs) suffice.

```python
def reduce_xi_mod_u(u_poly, i, g, R):
    poly = (R.gen()^i) % u_poly
    return [poly[j] for j in range(g)]

rows, rhs = [], []
for u_coeffs, v_coeffs in queries:
    u_poly = R(u_coeffs + [1])
    v_poly = R(v_coeffs)
    v2_mod_u = (v_poly * v_poly) % u_poly
    M = [reduce_xi_mod_u(u_poly, i, g, R) for i in range(deg_f+1)]
    for j in range(g):
        rows.append([M[i][j] for i in range(deg_f+1)])
        rhs.append(v2_mod_u[j])
A = Matrix(GF(p), rows); b = vector(GF(p), rhs)
f_sol = A.solve_right(b)
```

## Step 2 — When v is fully known but u unknown: factor (v² - f)

If v is fully known (e.g. from suffix XOR leaking specific bytes that align with v's coefficient
range), then u must be a **monic degree-g factor of (v² - f)**. (v² - f) has degree 2(g-1) or
2 deg f / however the degrees combine; e.g., g=7, deg f=15 → deg(v² - f) = 15.

Factor `v² - f` over GF(p)[x], enumerate monic degree-g divisors:

```python
target = v_poly^2 - f_poly
fac = list(target.factor())
candidates = []
def search(idx, deg_left, current):
    if deg_left == 0:
        u_cand = R(1)
        for k, g_ in current:
            u_cand *= g_^k
        candidates.append(u_cand.monic())
        return
    if idx >= len(fac): return
    g_, m = fac[idx]
    for k in range(0, m+1):
        if k * g_.degree() <= deg_left:
            search(idx+1, deg_left - k*g_.degree(), current + [(k, g_)])
search(0, g, [])
```

Typically only a handful of candidate u's exist — try each, decrypt with associated keystream,
filter by printable plaintext.

## Step 3 — Aligning byte windows

When the challenge XORs a known suffix with keystream, compute which uint64s fall fully inside
the known byte range `[c, c+len_suffix)`. Each uint64 i covers `[8i, 8i+8)`. With output ordering
`u[0..g-1] || v[0..g-1]`:
- If known window covers `[g*8, 2g*8)` exactly → v fully known, u unknown.
- If known window covers `[0, g*8)` → u fully known, v derivable from `v² ≡ f (mod u)` via
  factoring `f mod u` in `GF(p)[x] / u`.

## Worked example

Breizh CTF 2023 "What a Curve!" — g=7, p ≈ 2^64, f random degree-15. ct1 length = 112 = full
update, flag = 56 bytes, suffix = 56 bytes → known window aligns to v[0..6] exactly. Recover f
with 3 queries, factor v²-f → 2 monic deg-7 factors → flag.

## Pitfalls

- `int(coeff)` before `struct.pack`: Sage GF(p) elements need explicit cast.
- The challenge's `assert 0 not in rs and 1 not in rs` filters degenerate divisors but each
  fresh RNG call retries internally; on attacker side, just skip candidates with 0/1 entries.
- Mumford rep at infinity: deg u < g cases happen rarely; ensure 14 outputs (full g coeffs each).
