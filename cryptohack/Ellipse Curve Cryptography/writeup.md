# Ellipse Curve Cryptography

- **Category**: Brainteasers Part 2
- **Points**: 125

## Problem

A conic section (ellipse) is used instead of an elliptic curve. Points on x^2 + D*y^2 = 1 mod p form a group. Given a generator G and public key Q = n*G, find n.

## Approach

The discriminant D = 529 = 23^2, so sqrt(D) = 23 exists in Z_p. This means the conic is degenerate and the group is isomorphic to Z_p*.

Map each point (x, y) on the conic to z = x + 23*y in Z_p*. This converts the group operation (point addition on the conic) into multiplication mod p.

The DLP Q = n*G on the conic becomes z_Q = z_G^n mod p, a standard discrete logarithm in Z_p*. Since p-1 is smooth, Pohlig-Hellman solves it efficiently.

## Flag

```
crypto{c0n1c_s3ct10n5_4r3_f1n1t3_gr0up5}
```
