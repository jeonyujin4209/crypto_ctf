#!/usr/bin/env python3
"""
Successive Powers (60 pts)

{588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237}
are successive large powers of x modulo a three-digit prime p.

If these are x^k, x^(k+1), ..., x^(k+11) mod p, then:
  a[i+1] = a[i] * x mod p
  a[i+1] - a[i]*x ≡ 0 mod p
  => p divides (a[i+1] - a[i]*x) for all i

For any three consecutive values a, b, c:
  b = a*x mod p  =>  b*b = a*x * b = a * (b*x) = a*c mod p
  => b^2 - a*c ≡ 0 mod p
  => p divides (b^2 - a*c)

Take GCD of all such values to find p.
"""
from math import gcd

vals = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]

# p divides (b^2 - a*c) for consecutive triples
g = 0
for i in range(len(vals) - 2):
    a, b, c = vals[i], vals[i+1], vals[i+2]
    g = gcd(g, b*b - a*c)

# g might have small factors, find the three-digit prime
g = abs(g)
print(f"GCD = {g}")

# Factor out small primes to find p
for small in range(2, 100):
    while g % small == 0 and g // small >= 100:
        g //= small

p = g
print(f"p = {p}")

# Recover x: x ≡ vals[1] * pow(vals[0], -1, p) mod p
x = (vals[1] * pow(vals[0], -1, p)) % p
print(f"x = {x}")

# Verify
for i in range(len(vals) - 1):
    assert (vals[i] * x) % p == vals[i+1], f"Failed at index {i}"
print("Verified!")

print(f"\nFlag: crypto{{{p},{x}}}")
