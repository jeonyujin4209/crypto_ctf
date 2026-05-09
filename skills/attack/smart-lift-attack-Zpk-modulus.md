---
name: smart-lift-attack-Zpk-modulus
description: When EC scalar mul is mod p^k (prime power, k≥2) and |E(F_p)| is even prime, the reduction kernel ≅ (F_p,+) is exploitable. N=|E(F_p)| · P_lifted lands in kernel; formal log = -X·Z/Y mod p^k, divided by p, gives k mod p. One query, no smooth subgroup needed.
type: attack
---

# Smart-style lift attack on E(Z/p^k)

## Trigger

- Server source has scalar mul `mod modulus` (any formula: BJ x-only, full Weierstrass, etc.).
- modulus is **a prime power p^k** with k ≥ 2 (factordb returns `[(p, k)]`).
- `|E(F_p)|` is prime (so PH on F_p impossible) AND `|E_twist(F_p)|` is also prime (twist attack impossible).
- You can choose the input x0 (or full point) and get back x of (k * input).

This is the case when twist/PH/MOV are all blocked but the modulus structure itself leaks.

## Why it works

`E(Z/p^k) → E(F_p)` is a surjective group homomorphism. Its kernel for k=2 is the **formal group of E**, isomorphic to `(F_p, +)` for short Weierstrass curves with `p > 3`. Concretely, kernel elements in projective Weierstrass `(X : Y : Z)` have `X ≡ 0`, `Z ≡ 0 (mod p)`, with `Y` a unit.

Group order:  `|E(Z/p^2)| = p · |E(F_p)|`. So multiplying any P ∈ E(Z/p^2) by N := |E(F_p)| sends it into the kernel:

- `N · P_F = O` in E(F_p) (since N kills E(F_p))  
- ⇒ `N · P` reduces to `O` mod p  
- ⇒ `N · P` is in the kernel.

Formal log on the kernel:

```
ψ(K) = -X(K) · Z(K) / Y(K)   in Z/p^2     // Jacobian; for projective use -X/Y
```

For kernel K, `ψ(K) ∈ p · F_p`, so `ψ(K) / p ∈ F_p` is the additive log.

Given Q = k · P (server output, lifted to E(Z/p^k)):
```
ψ(N · Q) / ψ(N · P)  ≡  k  (mod p)
```

If `k < p` (which is true for typical CTF setups where order ≈ p and privkey < order), `k mod p = k` exactly. **One server query suffices.**

For k ≥ 3 the same idea generalizes (kernel is filtered by `p^i` powers; can recover k mod p^(k-1)).

## Recipe

1. **Detect**. factordb modulus → `[(p, k)]` with k ≥ 2. `|E(F_p)|` and `|E_twist(F_p)|` both prime.
2. **Build base point** P ∈ E(Z/p^k):
   - Pick `x0_F ∈ F_p` with `x0_F^3 + a·x0_F + b` a quadratic residue mod p.
   - Lift X0 := int(x0_F) (no extra mod-p^k contribution to X is fine).
   - Lift y via Newton step: from `y0_F = sqrt(rhs)` mod p, set `Y = Y0 + p·δ` where `δ = ((rhs_p^2 − Y0^2)/p) · (2·Y0)^(-1) mod p`. Verify `Y^2 ≡ rhs (mod p^k)`.
   - P = (X0, Y, 1) in Jacobian coords.
3. **Submit** X0 to server, get R = x of (k · P) mod p^k.
4. **Lift R** to (R, Y_R) on E(Z/p^k). Two y choices ⇒ ±k mod p ambiguity.
5. **Compute** N · P and N · Q with hand-coded Jacobian point arithmetic mod p^k.
   - Sage's `EllipticCurve(Zmod(p^k), ...)` may not work (Zmod is not a field). Hand-code dbl/add formulas. Standard Jacobian formulas don't need inversions during the loop.
6. **Formal log**:  `ψ((X, Y, Z)) = (-X · Z · Y^(-1)) mod p^k`, then `/ p` to get F_p element.
7. **Recover k mod p** = ψ(N·Q) · ψ(N·P)^(-1) mod p.
8. **Submit candidates**. From the 2 sign choices for y_R, you get 2 raw candidates {c, p-c}. The server's privkey is `min(k_mod_order, order - k_mod_order)`; it accepts any guess `g` with `g % order == privkey`. So enumerate `{c mod order, order - c mod order, (p-c) mod order, order - (p-c) mod order}` (≤ 4 unique) and `get_flag` each.

## Implementation pitfalls

- **Sage Integer ⇒ JSON**: wrap every Sage `Integer` with `int()` before `json.dumps`.
- **Sage `^` is power, not XOR**: in `.sage` files, BJ `pbit ^ bit` must be `pbit ^^ bit`.
- **Hensel lift edge case**: if y0_F = 0 (i.e., on order-2 point), can't divide by 2·Y0. Avoid: pick fresh x0.
- **Don't run the BJ x-only mult on Z/p^2 for the recovery step**: it doesn't expose y, so you can't get the full Jacobian (X, Y, Z) needed for the formal log. You MUST do full point arithmetic with explicit y.

## Attack cost / timing

- Build base: ~O(1) (Hensel lift + Sage random).
- Server query: 1 round-trip.
- N · P computed locally via Jacobian dbl/add over Z/p^2: ~256 doublings + ~128 adds, each a few mults mod p^2 (= 512-bit numbers). Takes ~0.5–2 sec in pure Python; faster in Sage.
- Formal log + division: O(1).
- **30-second TIMEOUT comfortable** with single submit-query loop.

## Challenges

- CryptoHack **An Exceptional Twisted Mind** (Parameter Choice 2, port 13417) — `crypto{no_need_for_twist_with_anomalous_attack_on_lift!}`. modulus = p^2, p = 2^256 − 189. |E(F_p)| = 256-bit prime, |twist| also prime. Server has `if GCD(R0[1], modulus) != 1: return "Infinity"` confirming designer aware of kernel-leak avenue but not blocking the lift attack itself. 30 sec TIMEOUT.

## Related

- `attack/xonly-ladder-quadratic-twist` — twist attack, what to try BEFORE this when |twist| has smooth structure
- `attack/invalid-curve-composite-modulus-twist-crt` — composite modulus N=p1·p2 case (different mechanism)
- `tools/factordb-prime-power-fingerprint` — modulus diagnosis
- `tools/brier-joye-x-only-recognition` — server-side formula identification

## Why "Smart attack" (the name)

Nigel Smart's 1999 attack recovered DLP on **anomalous curves** (where |E(F_p)| = p) by lifting to Q_p. Here the curve isn't anomalous, but the *ring* Z/p^2 forces a structurally similar kernel-of-reduction phenomenon. Same formal-group machinery, different trigger. Some authors call this "anomalous Z/p^2 attack" or just "lift attack on E(Z/p^k)."
