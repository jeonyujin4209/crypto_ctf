"""
Simplified Schoof's algorithm to compute #E(Fp) for y^2 = x^3 + ax + b.
Computes the trace of Frobenius t mod l for small primes l, then uses CRT.
"""
import math
from sympy import primerange
from sympy.ntheory.modular import crt

def poly_mod(f, g, p):
    """Compute f mod g over Z/pZ. Polynomials are lists [a0, a1, ..., an] where ai is coeff of x^i."""
    f = list(f)
    while len(f) > 0 and f[-1] % p == 0:
        f.pop()
    g = list(g)
    while len(g) > 0 and g[-1] % p == 0:
        g.pop()
    if len(f) == 0:
        return []
    if len(g) == 0:
        raise ZeroDivisionError
    while len(f) >= len(g):
        coeff = f[-1] * pow(g[-1], -1, p) % p
        for i in range(len(g)):
            f[len(f) - len(g) + i] = (f[len(f) - len(g) + i] - coeff * g[i]) % p
        while len(f) > 0 and f[-1] % p == 0:
            f.pop()
    return f

def poly_mul(f, g, p):
    """Multiply polynomials f and g over Z/pZ."""
    if not f or not g:
        return []
    result = [0] * (len(f) + len(g) - 1)
    for i in range(len(f)):
        for j in range(len(g)):
            result[i + j] = (result[i + j] + f[i] * g[j]) % p
    return result

def poly_mul_mod(f, g, mod_poly, p):
    """Multiply f*g mod mod_poly over Z/pZ."""
    return poly_mod(poly_mul(f, g, p), mod_poly, p)

def poly_pow_mod(f, n, mod_poly, p):
    """Compute f^n mod mod_poly over Z/pZ."""
    if n == 0:
        return [1]
    result = [1]
    base = list(f)
    while n > 0:
        if n & 1:
            result = poly_mul_mod(result, base, mod_poly, p)
        base = poly_mul_mod(base, base, mod_poly, p)
        n >>= 1
    return result

def poly_add(f, g, p):
    """Add polynomials."""
    result = [0] * max(len(f), len(g))
    for i in range(len(f)):
        result[i] = (result[i] + f[i]) % p
    for i in range(len(g)):
        result[i] = (result[i] + g[i]) % p
    while len(result) > 0 and result[-1] % p == 0:
        result.pop()
    return result

def poly_sub(f, g, p):
    """Subtract polynomials."""
    result = [0] * max(len(f), len(g))
    for i in range(len(f)):
        result[i] = (result[i] + f[i]) % p
    for i in range(len(g)):
        result[i] = (result[i] - g[i]) % p
    while len(result) > 0 and result[-1] % p == 0:
        result.pop()
    return result

def poly_scalar(f, c, p):
    """Multiply polynomial by scalar."""
    return [(x * c) % p for x in f]

def division_polynomials(a, b, p, n):
    """
    Compute the n-th division polynomial psi_n(x) for y^2 = x^3 + ax + b.
    Returns psi as a polynomial in x (absorbing y factors).

    Actually, for Schoof we need the division polynomials in a specific form.
    psi_0 = 0
    psi_1 = 1
    psi_2 = 2y (we represent as 1, since we'll handle y^2 = f(x) separately)
    psi_3 = 3x^4 + 6ax^2 + 12bx - a^2
    psi_4 = 4y(x^6 + 5ax^4 + 20bx^3 - 5a^2x^2 - 4abx - 8b^2 + a^3)

    For Schoof, we work with:
    f_n = psi_n for odd n (polynomial in x)
    f_n = psi_n / (2y) for even n (polynomial in x)

    And we replace y^2 with x^3 + ax + b wherever it appears.
    """
    # Store division polynomials as polynomials in x
    # For odd n: psi_n is a polynomial in x (with y^2 replaced by f(x))
    # For even n: psi_n / (2y) is a polynomial in x

    # We'll store "reduced" versions:
    # For odd n: store psi_n(x) directly
    # For even n: store psi_n(x) / (2y), which is a polynomial in x

    f_x = [b, a, 0, 1]  # x^3 + ax + b

    psi = {}
    psi[0] = []  # 0
    psi[1] = [1]  # 1
    psi[2] = [1]  # represents 2y / (2y) = 1
    psi[3] = [(-a*a) % p, (12*b) % p, (6*a) % p, 0, (3) % p]  # 3x^4 + 6ax^2 + 12bx - a^2
    psi[4] = poly_sub(
        poly_sub(
            poly_add(
                poly_add(
                    [0, 0, 0, 0, 0, 0, 1],  # x^6
                    [0, 0, 0, 0, (5*a) % p],  # 5ax^4
                    p
                ),
                [0, 0, 0, (20*b) % p],  # 20bx^3
                p
            ),
            [0, 0, (-5*a*a) % p],  # 5a^2x^2
            p
        ),
        poly_add(
            [0, (-4*a*b) % p],  # 4abx
            [(-8*b*b + a*a*a) % p],  # -8b^2 + a^3... wait
            p
        ),
        p
    )
    # Actually psi_4 / (2y) = x^6 + 5ax^4 + 20bx^3 - 5a^2x^2 - 4abx - 8b^2 + a^3
    psi[4] = [(-8*b*b + a**3) % p, (-4*a*b) % p, (-5*a*a) % p, (20*b) % p, (5*a) % p, 0, 1]

    return psi


def schoof(a, b, p):
    """
    Schoof's algorithm to compute #E(Fp) for y^2 = x^3 + ax + b.
    Returns the order of the curve.
    """
    # We need the trace t such that #E = p + 1 - t.
    # Hasse bound: |t| <= 2*sqrt(p).
    bound = 2 * int(math.isqrt(p)) + 1

    # We'll compute t mod l for small primes l until the product > 2*bound.
    traces = []
    moduli = []
    product = 1

    f_x = [b, a, 0, 1]  # x^3 + ax + b = y^2

    for l in primerange(2, 500):
        if product > 2 * bound:
            break

        if l == 2:
            # t ≡ 0 mod 2 iff gcd(x^p - x, x^3 + ax + b) is non-trivial
            # i.e., x^3 + ax + b has a root mod p
            # Compute x^p mod (x^3 + ax + b) mod p
            xp = poly_pow_mod([0, 1], p, f_x, p)  # x^p mod f(x)
            g = poly_sub(xp, [0, 1], p)  # x^p - x mod f(x)
            # GCD of g and f_x
            from math import gcd as mgcd
            def poly_gcd(a_poly, b_poly, p):
                while b_poly:
                    a_poly, b_poly = b_poly, poly_mod(a_poly, b_poly, p)
                return a_poly

            d = poly_gcd(f_x, g, p)
            if len(d) > 1:  # degree > 0
                t_mod_l = 0
            else:
                t_mod_l = 1

            print(f"  l=2: t ≡ {t_mod_l} (mod 2)")
            traces.append(t_mod_l)
            moduli.append(2)
            product *= 2
            continue

        # For odd prime l:
        # We work modulo the l-th division polynomial psi_l(x).
        # The Frobenius endomorphism phi acts on E[l] as:
        # phi^2(P) - [t]phi(P) + [p]P = O  for all P in E[l]
        # where t is the trace mod l.
        #
        # In terms of x-coordinates (working modulo psi_l and y^2 = f(x)):
        # We need to find t mod l such that:
        # (x^(p^2), y^(p^2)) + [p mod l](x, y) = [t](x^p, y^p)
        #
        # This requires computing with division polynomials, which is complex.
        # For simplicity, let me skip the full Schoof implementation and use
        # a different approach.

        # Actually, implementing full Schoof for arbitrary l is very involved.
        # Let me just compute for l=2 and l=3 and see if that's enough.
        # It won't be enough (need ~130 bits), but let's see.

        print(f"  Skipping l={l} (full Schoof not implemented)")
        break

    print(f"Product of moduli: {product}")
    print("Full Schoof implementation needed but not available")
    return None


# Run
p = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a = 1
b = 4

print(f"Computing order of E: y^2 = x^3 + {a}x + {b} over F_{p}")
print(f"p has {p.bit_length()} bits")

# First, just get t mod 2
f_x = [b, a, 0, 1]  # x^3 + ax + b

print("Computing x^p mod (x^3 + x + 4) mod p ...")
xp = poly_pow_mod([0, 1], p, f_x, p)
print(f"x^p mod f(x) = degree {len(xp)-1}")
g = poly_sub(xp, [0, 1], p)

def poly_gcd(a_poly, b_poly, p):
    while b_poly:
        a_poly, b_poly = b_poly, poly_mod(a_poly, b_poly, p)
    return a_poly

d = poly_gcd(list(f_x), g, p)
print(f"gcd degree: {len(d)-1}")
if len(d) > 1:
    print("t ≡ 0 (mod 2), order is even")
else:
    print("t ≡ 1 (mod 2), order is odd")

# This gives us 1 bit. We need ~130 bits total.
# Full Schoof is needed but very complex to implement correctly.
print("\nFull Schoof not implemented. Need Sage or PARI for curve order.")
