#!/usr/bin/env sage
# Compute the order and factorization of the Smooth Criminal curve.
# Usage:  sage order.sage  (or via infra/sage-run.sh)

p = 310717010502520989590157367261876774703
a = 2
b = 3
E = EllipticCurve(GF(p), [a, b])
N = E.order()
print("order =", N)
print("factors =", factor(N))

# Write to a plain text file for the Python solver to consume
with open("order.txt", "w") as f:
    f.write(str(N) + "\n")
    for q, e in factor(N):
        f.write(f"{q} {e}\n")
