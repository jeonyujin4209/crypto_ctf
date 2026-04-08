# Working with Fields (10pts)
## Starter

## Description
The set of integers modulo NNN, together with the operations of both addition and multiplication forms a ring Z/NZ\mathbb{Z}/ N\mathbb{Z}Z/NZ. Fundamentally, this means that adding or multiplying any two elements in the set returns another element in the set.When the modulus is prime: N=pN = pN=p, we are additionally guaranteed a multiplicative inverse of every element in the set, and so the ring is promoted to a field. In particular, we refer to this field as a finite field denoted Fp\FpFp​.The Diffie-Hellman protocol works with elements of some finite field Fp\FpFp​, where the prime modulus is typically very large (thousands of bits), but for the following challenges we will keep numbers smaller for compactness.Given the prime p=991p = 991p=991, and the element g=209g = 209g=209, find the inverse element d=g−1d = g^{-1}d=g−1 such that g⋅dmod  991=1g \cdot d \mod 991 = 1g⋅dmod991=1.
