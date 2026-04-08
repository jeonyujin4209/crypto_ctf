#!/usr/bin/env python3

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

p, q = 26513, 32321
g, u, v = egcd(p, q)
print(f"gcd={g}, u={u}, v={v}")
print(f"Answer: {min(u, v)}")
# p*u + q*v = gcd(p,q) => 26513*10245 + 32321*(-8404) = 1
# Answer: -8404
