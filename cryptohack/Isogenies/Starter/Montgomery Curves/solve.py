"""
Convert y^2 = x^3 + a*x + b to Montgomery form y^2 = x^3 + A*x^2 + x.

Standard procedure:
  1) Find a root alpha of x^3 + a*x + b = 0 (a point (alpha, 0) of order 2).
  2) Shift x -> x' + alpha, giving y^2 = x'^3 + (3*alpha)*x'^2 + (3*alpha^2+a)*x'.
  3) Scale: set s such that s^2 = (3*alpha^2 + a)^{-1}; then letting
        x' = s*X, y = s^(3/2)*Y (or equivalently u^2 substitution),
     we get Y^2 = X^3 + A*X^2 + X with A = 3*alpha*s.
"""
from sympy import isprime

p = 1912812599
a = 312589632
b = 654443578

# Find a root of x^3 + a*x + b mod p. Try brute / Tonelli-Shanks free approach:
# since p is small-ish we try searching via cubic roots; first factor by finding a linear factor.
def poly_eval(x):
    return (pow(x, 3, p) + a * x + b) % p

# Use sympy's nroots over GF(p)
from sympy import symbols, Poly, GF
x = symbols('x')
f = Poly([1, 0, a, b], x, domain=GF(p))
roots = f.ground_roots()
print("Roots of x^3 + a*x + b:", roots)

alpha = None
for r, _ in roots.items():
    alpha = int(r) % p
    if poly_eval(alpha) == 0:
        break
assert alpha is not None, "No root found"
print(f"alpha = {alpha}")

# Need s such that s^2 = (3*alpha^2 + a)^{-1} mod p.
inv_arg = (3 * alpha * alpha + a) % p
inv = pow(inv_arg, -1, p)

# Compute sqrt(inv) mod p.
def tonelli_shanks(n, p):
    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # general case
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while True:
        if t == 1:
            return r
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b2 = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b2 * b2) % p
        t = (t * c) % p
        r = (r * b2) % p

s = tonelli_shanks(inv, p)
if s is None:
    print("no sqrt, try other root")
else:
    A = (3 * alpha * s) % p
    print(f"A = {A}")
    # Also consider -s:
    A2 = (3 * alpha * ((-s) % p)) % p
    print(f"A (other sign) = {A2}")
    print(f"crypto{{{min(A, A2)}}}  or  crypto{{{max(A, A2)}}}")

# Try all roots if needed
print()
print("Trying all alpha candidates:")
for r, _ in roots.items():
    alpha = int(r) % p
    arg = (3 * alpha * alpha + a) % p
    inv = pow(arg, -1, p)
    s = tonelli_shanks(inv, p)
    if s is None:
        print(f"alpha={alpha}: no valid s (not a QR)")
        continue
    for sign in (s, (-s) % p):
        A = (3 * alpha * sign) % p
        print(f"alpha={alpha}, s={sign}: A={A}")
