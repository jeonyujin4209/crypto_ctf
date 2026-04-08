# Adrien's Signs

- **Category**: Brainteasers Part 1
- **Points**: 80

## Problem

Given a prime p and generator a, each bit of the flag is encrypted as c = a^(r*e) mod p where r is random. Recover the flag from the list of ciphertexts.

## Approach

Legendre symbol attack. Since a is a quadratic residue mod p, any power a^e is also a QR. The encryption randomizes via r, but the Legendre symbol leaks the bit:

- **Bit = 1**: c is a QR mod p, so Legendre(c, p) = 1
- **Bit = 0**: c is a QNR mod p, so Legendre(c, p) = -1

Compute the Legendre symbol for each ciphertext, map to bits, convert to bytes.

## Flag

```
crypto{p4tterns_1n_re5idu3s}
```
