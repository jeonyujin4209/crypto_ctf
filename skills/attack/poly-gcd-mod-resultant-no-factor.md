---
name: poly-gcd-mod-resultant-no-factor
description: Find x with maximal gcd(f(x), g(x)) (= the resultant R) by running polynomial Euclidean over Zmod(R)[x]; remainder stalls at degree-1 polynomial whose root is the simultaneous CRT-root mod R, no factoring of R required
type: attack
---

# Polynomial GCD modulo unknown-factorization resultant

## Pattern

Server gives you `f(x), g(x) ∈ Z[x]` (irreducible, coprime over Q, e.g. `x^13 + 37` and `(x+42)^13 + 42`) and uses `gcd(f(x), g(x))` (integer gcd) for some user-supplied `x`. To make the gcd huge you want `x` to be a simultaneous root of `f, g (mod R)` where `R = |Res(f,g)|`. R can be 900+ bits with no smooth factor — factoring infeasible.

Trick: compute polynomial Euclidean on `f, g` viewed in `Zmod(R)[x]`. Sage's `%` on polynomials over a non-field ring does **not** clear the leading-coefficient when the leading coefficient is a non-unit. The chain stalls early on a polynomial of low degree (typically degree 1) whose coefficients still carry the simultaneous CRT structure mod R. Solving that linear polynomial gives x.

## Why it works

For each prime power `p^k || R`, both `f, g` share a root mod `p^k`. By CRT, there's `x_0 mod R` with `f(x_0) ≡ g(x_0) ≡ 0 (mod R)`. The polynomial `(X - x_0)` divides both `f, g` in `Zmod(R)[X]`. Sage's polynomial Euclidean accumulates this factor: when the leading coefficient of the next remainder is a zero-divisor in `Z/R`, Sage simply leaves it instead of inverting — so the chain ends with a polynomial whose roots include `x_0`.

In practice for two coprime degree-n polynomials with squarefree resultant, the last non-trivial remainder is exactly degree 1: `a·x + b` with `a` invertible mod R and `x_0 = -b/a mod R`.

## Sage recipe

```python
x = polygen(ZZ)
f = ...   # Z[x]
g = ...   # Z[x]
v = abs(ZZ(f.resultant(g)))           # huge unfactored modulus
R = Zmod(v)
ff = f.change_ring(R)
gg = g.change_ring(R)
while gg:
    ff, gg = gg, ff % gg              # Sage's % handles non-unit leading coefficients
# ff is degree 1: ff = ff[1]*x + ff[0]
x_int = ZZ(-ff[0] / ff[1])            # 1/ff[1] in Z/v, then lift
# now gcd(f(x_int), g(x_int)) == v
```

## When to suspect

- Server prints `flag[:gcd(f(x), g(x))]` or otherwise rewards large integer gcd.
- `f, g ∈ Z[x]` coprime over Q (irreducible by Eisenstein etc.); resultant is large composite with no smooth factors.
- Trial-div / Pollard-rho / B1-50K ECM all fail to factor R within minutes — that's the signal you should NOT factor at all.

## Pitfalls

- `f.resultant(g)` may be negative; take `abs(...)`.
- If `ff[1]` is itself a zero-divisor in `Z/v`, the linear root extraction fails; the gcd stalled at higher degree. Then you may need to factor the constant `gcd(ff[1], v)` to split the modulus and retry per factor — but the squarefree-resultant case (most CTFs) leaves `ff[1]` invertible.
- The trick only works because Sage's polynomial `%` over `Zmod(N)` does pseudo-division-style behavior. Hand-rolling Python Euclidean with explicit `pow(lc, -1, R)` (raising on non-invertible) will instead succeed with all leading coefficients invertible and end with a non-zero constant coprime to R — wrong answer. Use Sage's built-in.

## Reference

ImaginaryCTF Round 40 / Leet Universe (maple3142). Idea-mate: math.stackexchange Q on `gcd(a^n+b, a^(n-1)+b)`.
