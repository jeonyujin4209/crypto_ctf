---
name: xonly-ladder-quadratic-twist
description: x-only XZ/Montgomery ladder doesn't validate point on E → submit x with non-residue x^3+ax+b puts computation on quadratic twist E'. If T = 2(q+1)-n smooth, recover d via PH on E'.
type: attack
---

# x-only Ladder Twist Attack

## Trigger pattern

Server exposes `shout(x, d) -> x([d]P)` via Montgomery/XZ ladder where the
ladder formulas only use `(a, b)` (e.g., the 2002-Izu-Takagi xz-ladder formulas
from hyperelliptic.org/EFD). No y-coordinate, no on-curve check possible
(can't tell from x alone).

The XZ ladder works identically for points on E (`y^2 = x^3 + ax + b`) and
its quadratic twist E' (`d * y^2 = x^3 + ax + b`, d non-residue). Sending an
x where `x^3 + ax + b` is a non-residue puts the computation in E'.

If `#E = n` is prime (no PH on E), check `T = #E' = 2(q+1) - n`. If T is
smooth, attack the twist instead.

## Steps

1. **Verify smooth twist:** `factor(2*(q+1) - n)`. Want product of "DLP-feasible"
   factors > secret bound.
2. **Build twist E' explicitly in Sage:**
   - Find non-residue `nr ∈ F_q*`
   - `E' (short Weierstrass form) : Et = EllipticCurve(F_q, [a*nr^2, b*nr^3])`
   - Verify `Et.order() == T`
3. **For each prime r | T:**
   - `P_r = (T // r) * Et.gen(0)`, `assert P_r.order() == r`
   - Map x to oracle: `x_oracle = X_Et / nr (mod q)` (because the twist in
     form `nr*y^2 = x^3+ax+b` has `X_E' = X_Et / nr`)
   - Send `x_oracle` to server, receive `out = x([d] P_r)` in oracle representation
4. **Recover d mod r:**
   - Lift back: `X_Q_on_Et = out * nr (mod q)`, recover Y on Et by sqrt of
     `X^3 + a_t X + b_t`
   - `k = discrete_log(Q, P_r, ord=r, operation='+')`
   - **Sign ambiguity:** x-only loses sign, so `d mod r ∈ {k, r-k}`
5. **CRT all sign combinations** (2^(#non-trivial primes) candidates), test each
   against expected secret structure (ASCII-printable, etc.)

## Crashes and identity handling

If `[d] P_r = O` on the twist, ladder returns `Z = 0`, and the server's
`pow(0, -1, q)` raises ValueError. The connection dies.

- Treat `Traceback`/EOF response as **`d ≡ 0 (mod r)`** (no sign ambiguity).
- Reconnect for each query (one-shot per prime). FLAG env stays the same so
  d is consistent across reconnects.

## Key formula (twist mapping)

For E: y² = x³+ax+b and twist E': nr·y² = x³+ax+b (nr non-square):
- Short Weierstrass form of E': `Et : y² = x³ + a·nr²·x + b·nr³`
- Coordinate map: `(X_Et, Y_Et) → (X_Et/nr, Y_Et/nr^(3/2))` ∈ E' affine
- For x-only oracle on E (which secretly works on E' too): send `x_oracle = X_Et / nr`

## Compared to invalid-curve-attack-alternative-b

- Invalid curve attack: uses (x, y) submission, scans many b' values, gets one
  small factor per curve. Needs full point.
- x-only ladder twist: only one extra group (the twist), but if T is fully
  smooth, single twist suffices. Cleaner.

## Reference solve

`cryptohack/CTF Archive/2023/Twist and shout (ECSC 2023 (Norway))/solve.sage`
- q = 2^128 - 159, T smooth (max prime ~2^37)
- Flag content < 2^128, single CRT result
- Identity-on-r mode handled via Traceback detection
