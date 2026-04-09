"""
We know phi(P), phi(Q) lie on the target short-Weierstrass curve
   E' : y^2 = x^3 + a*x + b  mod p
with p=63079. Two unknowns a, b, two equations:
   y1^2 = x1^3 + a*x1 + b
   y2^2 = x2^3 + a*x2 + b
"""
p = 63079
x1, y1 = 48622, 27709
x2, y2 = 9460, 13819

# Subtracting:
#   y1^2 - y2^2 = (x1^3 - x2^3) + a*(x1 - x2)
# => a = ((y1^2 - y2^2) - (x1^3 - x2^3)) / (x1 - x2)
num = ((y1 * y1 - y2 * y2) - (x1 ** 3 - x2 ** 3)) % p
den = (x1 - x2) % p
a = (num * pow(den, -1, p)) % p
b = (y1 * y1 - x1 ** 3 - a * x1) % p
print(f"E': y^2 = x^3 + {a}*x + {b} mod {p}")

# Sanity check
assert (y1 * y1) % p == (x1 ** 3 + a * x1 + b) % p
assert (y2 * y2) % p == (x2 ** 3 + a * x2 + b) % p

# Add (x1, y1) + (x2, y2) on the curve
def ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 % p == x2 % p:
        if (y1 + y2) % p == 0:
            return None
        # Doubling
        m = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        m = ((y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

R = ec_add((x1, y1), (x2, y2), a, p)
print(f"phi(P+Q) = {R}")
print(f"x-coordinate = {R[0]}")
print(f"crypto{{{R[0]}}}")
