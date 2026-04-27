---
name: rotation-invariants-norm-form-factoring
description: SO(2) rotation of two 2D integer vectors (x1,x2),(y1,y2) leaks 4 invariants — Gram entries Sx,Sy,Pxy plus det — enough to algebraically recover the integer pair and factor N=pq when both vectors satisfy the binary norm form x^2 + e y^2 = N.
type: attack
---

# Rotation invariants on a binary norm form leak factorization

## Setup
A challenge prints

```
F = RealField(K)
x = R(theta) * vector([x1, x2])
y = R(theta) * vector([y1, y2])
print(x); print(y)
```

with secret integers satisfying

```
x_i^2 + e * y_i^2 = N = p*q   (i = 1, 2)
```

`x_i ≤ 2^768`, `y_i ≤ 2^640`, `e` is a 256-bit prime, `(x1,y1) ≠ (x2,y2)`.

The "rotation hint" looks like noise — it's actually a complete leak.

## What is invariant under R∈SO(2) acting on column vectors?
Let `M = [[x1,x2],[y1,y2]]`. After the (same) rotation applied to both
column-vectors `(x1,x2)^T` and `(y1,y2)^T`, the new matrix is `M·R^T`.

- `M·M^T` is invariant → its three independent entries are public:
  - `Sx = x1^2 + x2^2`
  - `Sy = y1^2 + y2^2`
  - `Pxy = x1*y1 + x2*y2`
- `det(M) = x1*y2 − x2*y1` is invariant (det R = 1).

That's **4 algebraic equations** for **4 integer unknowns** plus the two
norm-form equations. Overdetermined → factorization.

## Step 1 — recover `e` exactly

Sum the two norm equations:

```
Sx + e * Sy = 2N            (★)
```

So `e = (2N − Sx) / Sy`. Even though `Sx` and `Sy` are floats with
~K-bit mantissa and absolute error ~`2·max(x_i)·2^{−K} = 2^{1535−K}`,
the *quotient* by `Sy ≈ 2^{1278}` collapses the noise: relative error
in `e` ≈ `2^{1535−K}/2^{1278} = 2^{257−K}`. With `K = 1337` that is
`2^{−1080}` — `round(...)` recovers `e` to the integer.

`is_prime(e)` is the sanity check.

## Step 2 — Sx, Sy as exact integers

Once `e` is known, **Sx is determined exactly** by (★): `Sx = 2N − e·Sy`.
For `Sy`, the printed `Sy_f` has absolute error `2·max(y_i)·2^{−K} ≈
2^{1280−K}`; with `K = 1337`, `round(Sy_f) = Sy` exactly.

(If `Pxy_f` is also small enough relative to `K`, just round it too;
otherwise carry it forward as a noisy float.)

## Step 3 — quadratic in v = y1²

Eliminate `x2, y2` using `x2² = Sx − x1²`, `y2² = Sy − y1²`. Set
`u = x1²`, `v = y1²`; then `u + e·v = N`. Square `Pxy − x1·y1 = x2·y2`:

```
2·Pxy·x1·y1 = Pxy^2 − Sx·Sy + N·Sy + (Sx − e·Sy)·v
(x1·y1)^2  = u·v = (N − e·v)·v
```

Substituting `x1·y1` and squaring kills the sign and yields a quadratic
in `v` with coefficients

```
A = Pxy^2 − Sx·Sy + N·Sy
B = Sx − e·Sy
(B^2 + 4·Pxy^2·e)·v^2 + (2·A·B − 4·Pxy^2·N)·v + A^2 = 0
```

Solve numerically in the high-precision field, round `v`, check
`u = N − e·v`, both `u` and `v` are perfect squares ⇒ `(x1, y1)`.
Then `x2 = isqrt(Sx − x1²)`, `y2 = isqrt(Sy − y1²)`.

## Step 4 — split N

`x1² + e·y1² ≡ 0 (mod p)` ⇒ `(x1 / y1)² ≡ −e (mod p)`, similarly mod q.
So at least one of

```
x1·y2 − x2·y1     and     x1·y2 + x2·y1
```

is divisible by `p` (and likewise by `q`, possibly the other one).
Since both factors are < N (≈ N^{0.91}), `gcd(., N)` returns a non-trivial
factor in at least one case.

## Why direct `gcd(N, det)` from the floats fails
`det = x1·y2 − x2·y1` is invariant, so you can compute it directly
from the printed rotated values. But its size is `2^{(768+640)} = 2^{1408}`,
*larger* than the field precision `K = 1337` ⇒ residual error after
subtraction is `~2^{71}`. That noise is small compared with `p ≈ 2^{768}`,
so in principle gcd should still pick up `p`… **but** it picks up `p`
only when `det` is *exactly* divisible by `p` — adding noise breaks the
exact divisibility and gcd returns 1. Hence the algebraic Step 3 above
(which yields *integer* x_i, y_i) is necessary.

## Recipe sketch (Sage)

```python
F = RealField(1337)
Sx_f = x1f^2 + x2f^2
Sy_f = y1f^2 + y2f^2
Pxy_f = x1f*y1f + x2f*y2f
Sy = ZZ(round(Sy_f))
e  = ZZ(round((2*n - Sx_f)/Sy_f));  assert is_prime(e)
Sx = 2*n - e*Sy
A = Pxy_f^2 - Sx*Sy + n*Sy
B = Sx - e*Sy
c2 = B^2 + 4*Pxy_f^2*e
c1 = 2*A*B - 4*Pxy_f^2*n
c0 = A^2
v = ZZ(round((-c1 + sqrt(c1^2 - 4*c2*c0))/(2*c2)))   # or other root
u = n - e*v
x1, y1 = isqrt(u), isqrt(v)
x2, y2 = isqrt(Sx-x1^2), isqrt(Sy-y1^2)
p = gcd(x1*y2 - x2*y1, n) or gcd(x1*y2 + x2*y1, n)
```

## Generalization
Whenever a hint adds a *continuous-group action* (rotation, GL_2(R),
unitary…) to *integer* secrets, replace "what's hidden?" with
"what's invariant?". For SO(2) it's `M·M^T` and `det M`. The number
of independent invariants vs unknowns tells you whether the leak
is recoverable. If the secrets also satisfy an arithmetic relation
(here `x^2 + e y^2 = N`), the invariants almost always over-determine.

## Variants to keep in mind
- Reflection-only (det = −1) doubles the case work but same idea.
- 3D rotations: `M·M^T` (6 entries) + det (1) = 7 invariants for a
  2×3 matrix's 6 unknowns ⇒ still recoverable.
- Higher `RealField` precision is required when `x_i·y_j > 2^K`.
  Use `K ≥ log2(N) + 100` to be comfortable.

## See also
- `tools/sage-preparser-xor-trap.md` — `^` is exponent, XOR is `^^`
- `tools/docker-windows-path-mount.md` — running the solver
