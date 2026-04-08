# Broken RSA

- **Category**: Brainteasers Part 1
- **Points**: 100

## Problem

RSA with a broken implementation. Given n, e=16, and ciphertext ct, recover the flag.

## Approach

Key insight: **n is actually prime** (verified via factordb). Since n is prime, there is no p*q factoring -- phi(n) = n - 1.

However, e = 16 = 2^4 and gcd(e, phi(n)) > 1, so the standard RSA decryption (modular inverse of e) does not work.

Instead, take **4 successive modular square roots** mod n using Tonelli-Shanks. Each square root has 2 solutions, giving 2^4 = 16 total candidates. Check each for a valid flag prefix.

## Flag

```
crypto{m0dul4r_squ4r3_r00t}
```
