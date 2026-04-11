---
name: hand-rolled-inverse-edge-cases
description: Challenge-provided `inverse(u, v)` via extended GCD may return 0 (not raise) on input 0. This silent behaviour enables "force z=0" bypass attacks.
type: feedback
---

Many CTF challenges inline a hand-rolled modular inverse via extended Euclid instead of calling `pow(u, -1, v)` or `gmpy2.invert`. The classic pattern:

```python
def inverse(u, v):
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1 < 0:
        u1 += v
    return u1
```

**Traced on `inverse(0, p)`:** u3 = 0, v3 = p. Loop runs once (v3 > 0), q = 0 // p = 0, v1 becomes 1, v3 becomes 0. Loop ends. Return u1 = 0. No exception, just silently returns 0 — which is not a mathematical inverse of 0 at all.

(For comparison, `pow(0, -1, p)` raises `ValueError`, as it should.)

**Why to care:** In ZKP/MPC challenges that use this helper inside a "guard", the guard often looks like `if (x * z) % p == 1: raise "nope"`. If the server runs `z = inverse(poly(our_input, x), p)` first and `poly` can be driven to 0, z becomes 0 silently, `x*0 != 1`, and the guard passes — leading to an identity-element attack.

**Concrete case: Couples (ZKP Challenges).** The server ran `z = inverse(poly(z_in, x), p)` where `poly(z_in, x) = x^(z_in + 7) - x^3 (mod p)`. Fermat lets us pick `z_in = p - 5` so that `x^(p+2) - x^3 = x^3 - x^3 = 0 mod p`, making `z = inverse(0, p) = 0`. BLS verification then reduces to `pairing(identity, *) == pairing(*, identity)` which is trivially 1, and the flag falls out.

**How to apply:**
- When the challenge provides a custom `inverse`, trace `inverse(0, v)` on paper before ruling out z=0 / scalar=0 attacks. If it silently returns 0, look for any path from your input to making the inverse input equal 0.
- The magic construction for making polynomial expressions 0 mod p is Fermat's little theorem: `x^k ≡ x^{k mod (p-1)} (mod p)` for `gcd(x, p) = 1`. Pick your input so that the polynomial degree lands on a term that already appears, cancelling to 0.
