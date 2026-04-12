# CSIDH Genus Theory / DDH-CGA Distinguisher

## When to use
- CSIDH-based challenge where you need to distinguish a DH shared secret from random
- Output has triples (EA, EB, EC) where bit=1 → EC = shared, bit=0 → EC = random
- Goal: recover each bit by applying the genus character function

## Key insight: genus character χ

For a CSIDH DH triple (EA, EB, EC=shared):
```
χ(base → EA) == χ(EB → EC)   ←→   EC is the real shared secret (bit=1)
```
For random EC: χ(base → EA) and χ(EB → EC) are independent ±1 (random).

**This requires NO DLP** — just evaluating a character function on curve coefficients.

## The supersingular delta function

```sage
def compute_supersingular_delta(E_0, E_test):
    """Genus character: returns ±1 for the isogeny class from E_0 to E_test."""
    Fx = PolynomialRing(E_0.base_field(), 'x')
    x = Fx.gen()
    a = E_0.a4()
    r    = (x^3 + a*x + E_0.a6()).roots()[0][0]    # root over GF(p^2)
    riso = (x^3 + E_test.a4()*x + E_test.a6()).roots()[0][0]
    char = ((E_test.a4() + 3*riso^2) / (a + 3*r^2))^((p - 1) // 4)
    return 1 if char == 1 else -1
```

This is the **weighted ratio of Weierstrass polynomial derivatives** at 2-torsion points,
raised to (p-1)/4 to get ±1 (a Legendre-like symbol).

## How to recover SECRET bits

```sage
for entry in challenge_data:
    EA = load_curve(entry['EA'])
    EB = load_curve(entry['EB'])
    EC = load_curve(entry['EC'])
    d_base_A = compute_supersingular_delta(base, EA)
    d_B_C    = compute_supersingular_delta(EB, EC)
    bit = "1" if d_base_A == d_B_C else "0"

# SECRET is stored as LSB-first bits
secret = int(key_bits[::-1], 2)
```

## CSIDH parameters for this challenge

```
ls = list(primes(3, 112)) + [139]   # 27 small odd primes
p = 2 * prod(ls) - 1
Fp2 = GF(p^2, modulus=[3, 0, 1])   # w^2 = -3
base = EllipticCurve(Fp2, [0, 1])   # y^2 = x^3 + 1
```

Key property: base has a4=0, so `a + 3*r^2 = 0 + 3*(-1)^2 = 3` (since r=-1 is root of x^3+1).

## Why j-invariant / Legendre symbol approaches fail

- Legendre(j[0], l): wrong character (doesn't satisfy bilinearity for DH triples)
- Norm(j) or Trace(j): also wrong
- The correct character uses **curve roots** (2-torsion x-coords), not j-invariant
- Reference: "Definition 4 (DDH-CGA)" in the isogeny DDH paper from the challenge hints

## Reference
- DDH-CGA paper (challenge hint): Definition 4, bilinear genus character
- Implementation: `cryptohack/Isogenies/Isogeny Challenges/A True Genus/solve.sage`

## Challenges
- CryptoHack: A True Genus (150pts) — `crypto{Gauss_knew_how_to_break_CSIDH???}`
