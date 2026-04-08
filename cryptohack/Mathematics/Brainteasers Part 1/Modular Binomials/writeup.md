# Modular Binomials

- **Category**: Brainteasers Part 1
- **Points**: 80

## Problem

Given N = p*q and:
```
c1 = (2*p + 3*q)^e1 mod N
c2 = (5*p + 7*q)^e2 mod N
```
Find p and q.

## Approach

Working mod p: c1 ≡ (3q)^e1, c2 ≡ (7q)^e2. Raise to cross-exponents:

```
c1^e2 ≡ (3q)^(e1*e2) mod p
c2^e1 ≡ (7q)^(e1*e2) mod p
```

Then: 7^(e1*e2) * c1^e2 - 3^(e1*e2) * c2^e1 ≡ 0 mod p.

Compute this value mod N and take GCD with N to recover p, then q = N // p.

## Flag

The flag is `crypto{p,q}` with the two recovered primes.
