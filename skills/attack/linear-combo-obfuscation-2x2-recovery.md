---
name: linear-combo-obfuscation-2x2-recovery
description: 비밀 P,Q가 R_i = a_i*P + b_i*Q (a_i, b_i 공개) 형태로 마스킹돼 있을 때, 두 샘플의 2x2 Cramer로 P, Q 즉시 복구
type: attack
---

# Linear Combo Obfuscation: 2x2 Cramer Recovery

## When to use

Challenge gives N samples `(a_i, b_i, R_i)` with
```
R_i = a_i * P + b_i * Q
```
where `a_i, b_i` are public scalars (random) and the goal involves `P` or `Q`
(both hidden). Often `Q = secret * P` and the secret = log_P(Q).

The challenge author hopes you can't separate P and Q. In fact **two samples are enough** — the linear system is 2×2 and invertible w.h.p.

## Recipe

Pick samples 0 and 1. View as 2D linear system over the scalar group:
```
| a_0  b_0 | | P |   | R_0 |
| a_1  b_1 | | Q | = | R_1 |
```
Cramer's rule with determinant `D = a_0*b_1 - a_1*b_0`:
```
P = (b_1 * R_0 - b_0 * R_1) * D^{-1}        (mod ord)
Q = (a_0 * R_1 - a_1 * R_0) * D^{-1}        (mod ord)
```
`D^{-1}` is taken modulo the group order (curve order, or any group `R_i` lives in).

```python
# Sage example (elliptic curve)
n = E.order()
a0, b0, R0 = ...
a1, b1, R1 = ...
D = (a0*b1 - a1*b0) % n
Dinv = inverse_mod(D, n)
P = Dinv * (b1*R0 - b0*R1)
Q = Dinv * (a0*R1 - a1*R0)
assert a0*P + b0*Q == R0
```

If `gcd(D, ord) != 1` (very rare for random a, b), pick different sample pair.

## After recovery

If the underlying secret is `Q = secret * P`, this becomes a standard ECDLP /
DLP. Check for smooth order → Pohlig-Hellman (`discrete_log` in Sage).

## Why it works

The "many random combinations" structure adds zero security — it's just an
overdetermined linear encoding. A single 2-sample solve undoes it, regardless
of how many extra samples are provided.

## Challenge

ECSC 2023 (Norway) — *Hide and seek*: 42 random `(a, b, aP + bQ)` over a curve with smooth order. After 2x2 recovery, `discrete_log(Q, P)` finishes.
Flag: `ECSC{l0g_pr0perty_w0rks_d1scr3t3ly_9d03dde5}`
