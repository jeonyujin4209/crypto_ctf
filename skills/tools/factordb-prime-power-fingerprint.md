---
name: factordb-prime-power-fingerprint
description: factordb response `[(p, k)]` with k ≥ 2 means modulus = p^k (prime power). Completely different vulnerability family from `[(p1,1),(p2,1)]` (RSA-style two-prime). Always inspect the exponent.
type: tool
---

# factordb prime-power fingerprint

## What to look for

`factordb` returns `factors` as a list of `[prime, exponent]` pairs:

```
{"status":"FF","factors":[["115792089237316195423570985008687907853269984665640564039457584007913129639747",2]]}
```

The `2` (or any k ≥ 2) is the giveaway: modulus is **p^k**, not a product of distinct primes.

## Why this matters (it's a different attack family)

| Modulus shape | Typical attack |
|---|---|
| `p · q` (two distinct primes) | Invalid curve / twist attack via CRT decomposition; RSA factor recovery; bivariate Coppersmith |
| `p^k` (prime power, k ≥ 2) | **Lift attack on E(Z/p^k)** (formal group / Smart-style); LWE reduction modulus collapse; Hensel-style Newton lifts |
| `p` (single prime) | Standard ECDLP / RSA — needs other vuln |

For EC scalar mul mod p^k, even when `|E(F_p)|` is a strong prime, the **reduction kernel** `E(Z/p^k) → E(F_p)` is isomorphic to (F_p, +) (an additive group with trivial DLP). One server query exploits this. See `attack/smart-lift-attack-Zpk-modulus`.

## Common misreads I should avoid

- "factordb returned 1 factor → modulus is prime, must be standard ECDLP." Wrong if exponent > 1. Always parse the **exponent**, not just the count of distinct primes.
- "Two primes, both 256-bit, similar size → RSA-N." Could also be `(p, p+ε)` quadratic-twist setup or CRT-EC (see `attack/invalid-curve-composite-modulus-twist-crt`). Look at the *use case*, not just the shape.
- "Sage `factor()` showed `p^2` so I don't need factordb." Yes — but check exponent in either case.

## Workflow

```python
def diagnose_modulus(N):
    from sympy import factorint, isprime
    if isprime(N):
        return ("prime", N)
    # Try factordb first (see tools/factordb-lookup-first)
    facs = factordb(N)
    if facs is None:
        return ("unknown", N)
    if len(facs) == 1:
        p, k = facs[0]
        if k >= 2:
            return ("prime_power", p, k)  # ⇒ lift attack candidate
        return ("prime", p)
    return ("composite", facs)
```

## Other prime-power triggers (not just EC)

- **RSA mod p^2** ("Takagi RSA"): private decryption faster, but lattice attacks differ.
- **Paillier mod p²·q²**: special form; check exponents.
- **Z/p^k Lattices**: LWE / LWR over prime-power modulus has its own reductions (HNF, Smith normal form).

If any of these appear with non-unit exponent, the attack landscape is different — don't reach for the standard "two prime" toolkit.

## Related
- `tools/factordb-lookup-first` — how to query factordb in the first place
- `attack/smart-lift-attack-Zpk-modulus` — main exploit when EC + p^k
