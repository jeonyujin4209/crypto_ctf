---
name: isogeny-claw-mitm
description: 2^e-isogeny E1→E2를 MITM claw-finding으로 복구. j-invariant DFS 양방향 + 고정점 매칭 → 경로 재구성 → 포인트 push
type: skill
---

# Isogeny Claw / MITM Attack (2-isogeny graph)

## When to use
- Given two elliptic curves E1, E2 known to be connected by a 2^e-isogeny
- The isogeny (or its torsion images) is unknown / missing
- Goal: recover the isogeny phi: E1 → E2, then push torsion points through it

## Key insight: Φ2 modular polynomial for j-invariant traversal

Do NOT compute actual isogenies during the graph search. Instead:
1. Traverse the j-invariant graph using the degree-2 **modular polynomial Φ2**
2. Only build actual isogenies for the ~e steps along the recovered path

This is 100-1000x faster than constructing isogenies at every BFS step.

## Φ2 modular polynomial neighbors

```sage
def generic_modular_polynomial_roots(j1):
    """3 j-invariant neighbors of j1 in 2-isogeny graph (first call, no parent)"""
    R = PolynomialRing(j1.parent(), 'y')
    y = R.gens()[0]
    Phi2 = (
        j1**3 - j1**2*y**2 + 1488*j1**2*y - 162000*j1**2
        + 1488*j1*y**2 + 40773375*j1*y + 8748000000*j1
        + y**3 - 162000*y**2 + 8748000000*y - 157464000000000
    )
    return Phi2.roots(multiplicities=False)

def quadratic_modular_polynomial_roots(jc, jp):
    """2 remaining j-invariant neighbors of jc, given parent jp (avoids backtrack)"""
    jc2 = jc**2
    alpha = -jc2 + 1488*jc + jp - 162000
    beta = (jp**2 - jc2*jp + 1488*(jc2 + jc*jp)
            + 40773375*jc - 162000*jp + 8748000000)
    return quadratic_roots(alpha, beta)  # solve x^2 + alpha*x + beta = 0
```

## MITM DFS algorithm

```sage
e1 = floor(e / 2)   # depth from E1
e2 = e - e1          # depth from E2 (larger side, stops early on collision)

# Build full j-inv graph from E1 at depth e1
graph1, _ = j_invariant_isogeny_graph(j1, e1)
middle = set(graph1[e1].keys())   # all leaf j-invariants

# DFS from E2, stop as soon as we hit any middle j-invariant
graph2, j_mid = j_invariant_isogeny_graph(j2, e2, middle_j_vals=middle)
```

Key: the DFS from E2 terminates **early** once a collision is found — on average visits O(2^(e/2)) nodes total.

## Reconstruct isogeny from j-path

```sage
def brute_force_isogeny_jinv(E1, j2, l):
    """Find degree-l isogeny from E1 to curve with j-invariant j2"""
    f = E1.division_polynomial(l)
    for x, _ in f.roots():
        K = E1.lift_x(x); K._order = ZZ(l)
        phi = EllipticCurveIsogeny(E1, K, degree=l, check=False)
        if phi.codomain().j_invariant() == j2:
            return phi
    raise ValueError(f"no degree-{l} isogeny to j={j2}")

# Build composite isogeny from the 35-step path
from sage.schemes.elliptic_curves.hom_composite import EllipticCurveHom_composite
factors = []
E = E1
for j_next in j_path[1:]:
    phi = brute_force_isogeny_jinv(E, j_next, 2)
    factors.append(phi); E = phi.codomain()
phi_A = EllipticCurveHom_composite.from_factors(factors)

# Fix endpoint with isomorphism
iso = phi_A.codomain().isomorphism_to(E2)
phi_A = iso * phi_A
```

## sqrt in GF(p²) (needed for quadratic_roots)

```sage
def sqrt_Fp2(a):
    p = Fp2.characteristic()
    ii = Fp2.gens()[0]
    a1 = a ** ((p - 3) // 4)
    x0 = a1 * a; alpha = a1 * x0
    if alpha == -1: return ii * x0
    b = (1 + alpha) ** ((p - 1) // 2)
    return b * x0

def quadratic_roots(b, c):
    d2 = b**2 - 4*c; d = sqrt_Fp2(d2)
    return ((-b + d) * Fp2_inv_2, -(b + d) * Fp2_inv_2)
```

## Why my BFS-per-isogeny approach fails

- Computing `E(0).division_points(2)` + `E.isogeny(P)` per node: O(2^e) expensive isogeny constructions
- Memory: storing full curve + isogeny objects for each node
- Dual chain reconstruction is tricky and error-prone
- Correct approach: j-invariant traversal (cheap arithmetic) → only build isogenies on the 35-step path

## Full example (Meet me in the Claw)

```
ea=35, eb=29, p = 2^35 * 3^29 - 1
E0: y^2 = x^3 + x  (j=1728)
EA: Alice's public curve
phiA_P3, phiA_Q3: MISSING from source

After claw_finding_attack(E0, EA, 2, 35):
  K = phiA_P3 + sB * phiA_Q3
  E_shared = EA.isogeny(K, algorithm="factored").codomain()
  j_shared → SHA256 key → AES-CBC decrypt
```

## Reference
- Implementation: `cryptohack/Isogenies/Isogeny Challenges/Meet me in the Claw/solve.sage`
- GitHub repo with full library: isogeny claw-finding (mitm.py)

## Challenges
- CryptoHack: Meet me in the Claw (120pts) — `crypto{clawing_our_way_to_victory}`
