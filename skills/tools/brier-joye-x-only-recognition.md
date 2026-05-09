---
name: brier-joye-x-only-recognition
description: Recognize Brier-Joye x-only short-Weierstrass scalar mul in server source (dbl/diffadd pattern). Implies invalid-curve attack surface — formulas use only (a, b), no on-curve check possible.
type: tool
---

# Brier-Joye x-only formulas — fingerprint & implications

## Visual fingerprint in server source

Server has three function-style helpers and a ladder loop:

```python
def dbl(P1):
    X1, Z1 = P1
    XX = X1**2 % m; ZZ = Z1**2 % m
    A = 2 * ((X1 + Z1)**2 - XX - ZZ) % m
    aZZ = a * ZZ % m
    X3 = ((XX - aZZ)**2 - 2*b*A*ZZ) % m
    Z3 = (A * (XX + aZZ) + 4*b*ZZ**2) % m
    return (X3, Z3)

def diffadd(P1, P2, x0):
    X1, Z1 = P1; X2, Z2 = P2
    X1Z2 = X1*Z2 % m; X2Z1 = X2*Z1 % m; Z1Z2 = Z1*Z2 % m
    T = (X1Z2 + X2Z1) * (X1*X2 + a*Z1Z2) % m
    Z3 = (X1Z2 - X2Z1)**2 % m
    X3 = (2*T + 4*b*Z1Z2**2 - x0*Z3) % m
    return (X3, Z3)

def scalarmult(scalar, x0):
    R0 = (x0, 1)
    R1 = dbl(R0)
    n = scalar.bit_length()
    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0)
        R0 = dbl(R0)
        pbit = bit
    if bit:
        R0 = R1
    return R0[0] * inverse(R0[1], modulus) % modulus
```

Key markers:
- (X, Z) projective pair (no Y at all)
- `dbl` uses `4*b*ZZ**2` constant
- `diffadd` uses `4*b*Z1Z2**2 - x0*Z3` (the input x0 reappears in EACH addition — this is the "differential" part)
- `swap` based on `pbit XOR bit` (Montgomery ladder with constant-time conditional swap)
- Final `R0[0] * inverse(R0[1], modulus)` to deprojectify to affine x

Reference: Brier–Joye 2002 "Weierstraß elliptic curves and side-channel attacks", "x-only" formulas for short Weierstrass curves (analogous to Montgomery ladder).

## Vulnerability surface

Same as Montgomery x-only ladder:
1. **No on-curve check possible** — formulas don't even reference y. Any x0 is "valid input."
2. **Works equally on E and E_t** (quadratic twist). x0 maps to E if x0³+a·x0+b is QR mod p, else to E_t.
3. **Same formulas for E and E_t**: the (a, b) parameters of E are used; submitting x0 from E_t still computes scalar mul correctly on E_t over the implicit y in F_p².

## Attack moves

If you see this pattern + scalar is a long-term secret:
- **Twist attack on prime modulus**: `attack/xonly-ladder-quadratic-twist`. Compute |E_t| = 2p+2-|E|, factor for smooth part, submit x0 of smooth-order point on E_t, recover privkey via PH.
- **Twist attack on composite modulus**: `attack/invalid-curve-composite-modulus-twist-crt`. Each prime factor of N has its own twist; CRT compose smooth orders from each side.
- **Fault on Z=0**: if scalar mul ever lands on order-2 point (y=0 on the curve), `inverse(0, m)` raises and may leak through error channel.

## Common misreadings

- "Looks like Montgomery — must be safe with twist": NO, this is Weierstraß x-only. Same vuln class but different formulas. The b parameter matters.
- "Server checks `Q in E` — safe": with x-only API, server can't check (no y to plug in). The on-curve check would need `is_square(x³+a·x+b)`, which hardly any CTF source does.
- "`scalar.bit_length()` loop is constant-time, must be CT-secure": that's about side-channel resistance against power analysis. Doesn't help against algebraic attacks like invalid curve.

## Distinguishing from Montgomery curve

| Marker | Montgomery (X25519-style) | Brier-Joye Weierstraß |
|---|---|---|
| Curve eq | `B·y² = x³ + A·x² + x` | `y² = x³ + a·x + b` |
| `dbl` const | uses A | uses `4·b·ZZ²` |
| `diffadd` extra term | none for x0 (cancels) | `−x0·Z3` |
| Param flag in source | `A24 = (A+2)/4` precomputed | bare `a`, `b` |

If you see `4·b·...` constants, it's Brier-Joye. If you see `(A+2)/4` or `A24`, it's Montgomery.

## Related
- `attack/invalid-curve-composite-modulus-twist-crt` — full attack chain
- `attack/xonly-ladder-quadratic-twist` — Montgomery twist attack (similar exploit)
- `failures/invalid-curve-attack-alternative-b` — Weierstraß full-point version (Checkpoint, no x-only)
