from Crypto.Util.number import inverse, long_to_bytes
from sympy.ntheory import sqrt_mod

p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
gy = 225987949353410341392975247044711665782695329311463646299187580326445253608

Qx = 2582928974243465355371953056699793745022552378548418288211138499777818633265
Qy = 2421683573446497972507172385881793260176370025964652384676141384239699096612

# Recover a, b
a = (gy**2 - Qy**2 - gx**3 + Qx**3) * inverse(gx - Qx, p) % p
b = (gy**2 - gx**3 - a*gx) % p

print(f"a = {a}")
print(f"b = {b}")

# Discriminant is 0 => singular curve
disc = (4*a**3 + 27*b**2) % p
assert disc == 0, "Curve is not singular!"
print("Singular curve confirmed!")

# Find the singular point
# f(x) = x^3 + ax + b, f'(x) = 3x^2 + a
# The singular point has f(xs) = 0 and f'(xs) = 0
# From f'(xs) = 0: xs^2 = -a/3 mod p
# xs = sqrt(-a/3) mod p

neg_a_over_3 = (-a * inverse(3, p)) % p
xs = sqrt_mod(neg_a_over_3, p)
if xs is None:
    print("No sqrt => trying other approach")
else:
    print(f"Singular point x = {xs}")
    # Verify
    f_val = (xs**3 + a*xs + b) % p
    f_prime = (3*xs**2 + a) % p
    print(f"f(xs) = {f_val}")
    print(f"f'(xs) = {f_prime}")

# f(x) = (x - xs)^2 * (x - xo) where xo = -2*xs (from Vieta's: sum of roots = 0)
xo = (-2 * xs) % p
print(f"Other root xo = {xo}")

# Check: is it a node (xs != xo) or cusp (xs == xo)?
if xs == xo:
    print("CUSP: group isomorphic to (Fp, +)")
    # Map: substitute u = x - xs, then y^2 = u^3
    # Parameter t = y/u, so u = t^2, y = t^3
    # Group law maps to addition: t(P+Q) = t(P) + t(Q) (approximately)
    # Actually for cusp: map phi(x,y) = y / (x - xs), and phi(P1 + P2) = phi(P1) + phi(P2)

    def to_additive(px, py):
        return py * inverse((px - xs) % p, p) % p

    tG = to_additive(gx, gy)
    tQ = to_additive(Qx, Qy)
    d = tQ * inverse(tG, p) % p

else:
    print("NODE: group isomorphic to Fp* or subgroup of Fp2*")

    # For node: y^2 = (x - xs)^2 * (x - xo)
    # Let alpha^2 = xs - xo (if QR) or work in Fp2
    delta = (xs - xo) % p
    print(f"delta = xs - xo = {delta}")

    leg = pow(delta, (p-1)//2, p)
    print(f"Legendre symbol (delta/p) = {leg}")

    if leg == 1:
        print("delta is QR => group in Fp*")
        alpha = sqrt_mod(delta, p)
        print(f"alpha = {alpha}")

        # Map: phi(x,y) = (y + alpha*(x - xs)) / (y - alpha*(x - xs))
        # This is a multiplicative homomorphism: phi(P+Q) = phi(P) * phi(Q)
        def to_mult(px, py):
            xr = (px - xs) % p
            num = (py + alpha * xr) % p
            den = (py - alpha * xr) % p
            return num * inverse(den, p) % p

        tG = to_mult(gx, gy)
        tQ = to_mult(Qx, Qy)
        print(f"tG = {tG}")
        print(f"tQ = {tQ}")

        # DLP in Fp*: tG^d = tQ mod p
        # Order of Fp* is p-1. If p-1 is smooth, Pohlig-Hellman works.
        from sympy import factorint
        from sympy.ntheory import discrete_log
        factors = factorint(p - 1)
        print(f"p-1 factors: {factors}")
        max_factor = max(factors.keys())
        print(f"Largest factor: {max_factor} ({max_factor.bit_length()} bits)")

        if max_factor < 2**40:
            print("Smooth enough for Pohlig-Hellman!")
            d = discrete_log(p, tQ, tG)
        else:
            print("Large factor, trying anyway with sympy...")
            d = discrete_log(p, tQ, tG)
    else:
        print("delta is not QR => group in Fp2*")
        # Map to Fp2* and solve there
        # Elements are (a0, a1) representing a0 + a1*sqrt(delta)

        def fp2_mul(x, y):
            return ((x[0]*y[0] + x[1]*y[1]*delta) % p,
                    (x[0]*y[1] + x[1]*y[0]) % p)

        def fp2_inv(x):
            norm = (x[0]*x[0] - x[1]*x[1]*delta) % p
            inv_norm = pow(norm, -1, p)
            return (x[0]*inv_norm % p, (-x[1]*inv_norm) % p)

        def fp2_pow(base, exp):
            result = (1, 0)
            b = base
            while exp > 0:
                if exp & 1: result = fp2_mul(result, b)
                b = fp2_mul(b, b)
                exp >>= 1
            return result

        def to_fp2_mult(px, py):
            xr = (px - xs) % p
            # num = py + sqrt(delta) * xr = (py, xr)
            # den = py - sqrt(delta) * xr = (py, -xr)
            num = (py % p, xr % p)
            den = (py % p, (-xr) % p)
            return fp2_mul(num, fp2_inv(den))

        tG = to_fp2_mult(gx, gy)
        tQ = to_fp2_mult(Qx, Qy)
        print(f"tG = {tG}")
        print(f"tQ = {tQ}")

        # The image is in the norm-1 subgroup of Fp2*, which has order p+1
        check = fp2_pow(tG, p+1)
        print(f"tG^(p+1) = {check}")

        from sympy import factorint
        order = p + 1
        factors = factorint(order)
        print(f"p+1 factors: {factors}")

        # Pohlig-Hellman in Fp2*
        import math

        def fp2_dlog_bsgs(g, h, n):
            m = int(math.isqrt(n)) + 1
            baby = {}
            curr = (1, 0)
            for j in range(m):
                baby[curr] = j
                curr = fp2_mul(curr, g)
            g_inv = fp2_inv(g)
            giant = fp2_pow(g_inv, m)
            gamma = h
            for i in range(m + 1):
                if gamma in baby:
                    return i * m + baby[gamma]
                gamma = fp2_mul(gamma, giant)
            return None

        remainders = []
        moduli = []
        for prime, exp in factors.items():
            pe = prime ** exp
            cofactor = order // pe
            gi = fp2_pow(tG, cofactor)
            hi = fp2_pow(tQ, cofactor)

            if exp == 1:
                xi = fp2_dlog_bsgs(gi, hi, prime)
            else:
                g_base = fp2_pow(gi, prime**(exp-1))
                result = 0
                gamma = hi
                for k in range(exp):
                    hk = fp2_pow(gamma, prime**(exp-1-k))
                    dk = fp2_dlog_bsgs(g_base, hk, prime)
                    if dk is None:
                        print(f"BSGS failed for p={prime}, k={k}")
                        break
                    result += dk * prime**k
                    gamma = fp2_mul(gamma, fp2_inv(fp2_pow(gi, dk * prime**k)))
                xi = result

            print(f"  x ≡ {xi} (mod {pe})")
            remainders.append(xi)
            moduli.append(pe)

        from sympy.ntheory.modular import crt
        _, d = crt(moduli, remainders)

        # Verify in Fp2
        check = fp2_pow(tG, d)
        print(f"Verify in Fp2: {check == tQ}")

print(f"\nd = {d}")
flag = long_to_bytes(d)
print(f"Flag: {flag}")
