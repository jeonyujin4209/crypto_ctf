---
name: quaternion-conjugation-linear-recovery
description: Conjugation-based key exchange in quaternion algebra over Z/n. Recover secret chi from public (alpha, beta=chi^-1*alpha^-1*chi, gamma=chi^r) by combining two linear constraints (alpha*chi = chi*beta^-1 and gamma*chi = chi*gamma) to a 1-dim kernel of an 8x4 matrix mod n. Cofactor formula avoids modular inverses, so works with composite n.
type: attack
---

# Quaternion conjugation key exchange — linear constraint recovery

## Setup (typical)
Public key: `(n, alpha, beta, gamma)` over Q⊗Z/n where Q is Lipschitz quaternions.
- `alpha`, `chi` random quaternions over Z/n (n = pq, RSA-like)
- `beta = chi^-1 * alpha^-1 * chi` (so `alpha*chi = chi*beta^-1`)
- `gamma = chi^r` for random huge r (so chi commutes with gamma)

Encrypt: `delta = gamma^s` (random s), `eps = delta^-1 * alpha * delta`,
`kappa = delta^-1 * beta * delta`, `mu = kappa * k * kappa`. K = SHA256(str(k)) for AES.

## Key insight
Conjugation by `chi` is an automorphism. Once you know `chi` (up to scalar), you can
compute `kappa = chi^-1 * eps^-1 * chi` from public `eps`, then `k = kappa^-1 * mu * kappa^-1`.

Two linear equations on chi:
1. `alpha * chi - chi * beta^-1 = 0`  →  4 equations on chi's components
2. `gamma * chi - chi * gamma   = 0`  →  4 equations

Combined 8x4 system has rank 3 generically: kernel is 1-dim, giving chi up to a scalar.
Scalar ambiguity is harmless because conjugation by `c*chi` equals conjugation by `chi`.

## Linear maps
For quaternion `p = (pa, pb, pc, pd)`, left multiplication `q -> p*q` and right
multiplication `q -> q*p` are 4x4 matrices acting on `(a, b, c, d)^T`:

```
L_p = [[pa, -pb, -pc, -pd],          R_p = [[pa, -pb, -pc, -pd],
       [pb,  pa, -pd,  pc],                 [pb,  pa,  pd, -pc],
       [pc,  pd,  pa, -pb],                 [pc, -pd,  pa,  pb],
       [pd, -pc,  pb,  pa]]                 [pd,  pc, -pb,  pa]]
```

## Kernel via cofactors (no modular inverses needed)
For composite n, naive Gaussian elimination may hit non-invertible pivots. To recover
the 1-dim null space of an 8x4 matrix A reliably:

- Pick any 3 rows forming a 3x4 matrix B.
- Null vector: `v[j] = (-1)^j * det(minor obtained by removing column j)` (3x3 dets, integer arithmetic).
- Verify `A * v = 0 (mod n)`. If `v != 0` and verifies, done. Otherwise try another triple.

This works because cofactors give the cross-product-style perpendicular to the row span.

## Decryption
```python
chi_inv = chi_rec.invert()   # uses N(chi) = a^2+b^2+c^2+d^2; if not coprime to n,
                              # gcd reveals factor of n (bonus)
kappa = chi_inv * eps**-1 * chi_rec
k = kappa**-1 * mu * kappa**-1
K = sha256(str(k).encode()).digest()
```

## Sanity checks
- Conjugation preserves trace: `alpha.a == eps.a` and `beta.a == kappa.a` (the scalar component).
- After computing chi_rec: verify `alpha*chi_rec == chi_rec*beta^-1`.

## Generalization
Whenever you have `pub = chi^-1 * X * chi` AND `pub2 = chi^k` (any element commuting with chi)
in a non-commutative algebra where left/right multiplication is linear, this two-equation
linear-system recovery works to find chi up to a scalar. Only need:
- 2 independent commitments giving linear constraints on chi
- their combined null space is 1-dim (generically true)

Solved: Irish flan (ECSC 2023, Norway).
