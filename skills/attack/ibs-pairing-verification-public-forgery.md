---
type: attack
title: Pairing IBS verification protocol forgery — public Qid_admin
tags: [pairing, ibs, identity-based-signature, bn-curve, forgery, ate-pairing]
---

# Pairing-based IBS interactive verification — forge with public data only

## Setting

Identity-based signature with PKG master secret `s`, public params:
- `P_G1 = u*G1`, `P_G2 = u*G2`, `Q = s*P_G1`
- User keys: `du0 = s * Qid`, `du1 = s^-1 * Qid` where `Qid = H0(uid)`.
- Sign(m): `R = k*P_G1`, `S = k^-1 * du0 + H(m) * du1`.

Interactive 3-move verification (verifier picks fresh random `x, y`):
1. Verifier sends `C = x*y*R`.
2. Signer returns `t = e(R+Q, P_G2 - du1)`, `r = e(C, du1)`.
3. Verifier checks both
   - **Eq0:** `e(R, S)^x  ?=  e(Q, Qid)^x * r^(H(m)/y)`
   - **Eq1:** `r^(1/y) * t^x * e(P_G1, Qid)^x  ?=  e(R+Q, P_G2)^x`

   plus `t,r != 1` and `t^p == r^p == 1` (i.e., t,r in GT).

## Vulnerability

`Qid_uid = H0(uid)` is computed from PUBLIC curve data only — no PKG secret.
So **the attacker can compute `Qid_admin` directly**.

The protocol gives the prover too much algebraic freedom: by choosing the
"signature" `(R, S)` adversarially, the verifier's two equations collapse to
relations among publicly computable pairing values.

## Forgery (no admin secret, no DLP)

Set
- `R := Q`     (any G1 point with known relation to Q works)
- `S := Qid_admin + H(m) * Qid_user`  (Qid_user is your own — or any G2
  point you can compute pairings with)

Then
- **Eq0** becomes `e(Q, Qid_user)^(x*H(m)) = r^(H(m)/y)`,
  satisfied by `r = e(C, Qid_user) = e(Q, Qid_user)^(xy)`.
- **Eq1** becomes (after dividing by `x`) the *base equality*
  `e(Q, Qid_user) * t * e(P_G1, Qid_admin) = e(2Q, P_G2)`,
  giving `t = e(2Q, P_G2) / ( e(Q, Qid_user) * e(P_G1, Qid_admin) )`.

Send `(R, S)` first, receive `C`, compute `r` and `t` (both in GT
automatically — pairing outputs are in the order-`n` subgroup), submit.

## Why this works

The verifier raises everything to `x` (random in Z_n), and the order-`n`
subgroup is prime — so `^x` is injective. We need *base* equality, not just
"holds for the chosen x". The chosen `r = e(C, ·)` cleverly absorbs the `xy`
factor so that `r^(1/y)` reduces to `e(R, ·)^x`, neatly matching the `^x`
template.

## Generic recipe

Whenever an interactive pairing-based verifier:
1. picks blinding scalars `(x, y, ...)` privately,
2. publishes a *single* commitment `C = (xy...) * R` for adversary-chosen `R`,
3. checks pairing equations all raised to `x`,

then by setting `r = e(C, *known G2 point*)` we can sneak `xy` into the
exponent without ever recovering `x` or `y`. The verifier's challenge
randomness becomes useless because the relations collapse to base equality
in GT.

## Pitfalls / checks

- `r != 1` and `t != 1`: easy generically; pick `Y = Qid_user` if any pair
  is degenerate.
- `e(O, *)` raises (challenge asserts `P != O_EFp`). Avoid `R + Q = O`,
  i.e., do **not** send `R = -Q`.
- `e(P, Q)` constructor goes through `EFp(sig[0])` which rejects off-curve
  points — `R` must be a valid curve point.
- `H(m)` is the challenge's truncated SHA-256; recompute it locally to
  build `S`.

## Used in

- ECSC 2024 (Italy) — *Smithing contest* — full forgery, `R = Q`.
