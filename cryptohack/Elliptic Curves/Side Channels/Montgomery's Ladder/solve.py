"""
Montgomery's Ladder on Curve25519 (Montgomery form).
E: B*y^2 = x^3 + A*x^2 + x mod p, with A=486662, B=1, p=2^255-19.
G.x = 9, k = 0x1337c0decafe. Compute x-coordinate of [k]G.

Using affine Montgomery addition + doubling per the challenge statement,
with the standard Montgomery ladder that starts (R0,R1) = (P, [2]P).
"""

p = 2**255 - 19
A = 486662
B = 1


def inv(a, m=p):
    return pow(a, -1, m)


def mg_add(P, Q):
    # P != Q, neither is infinity
    x1, y1 = P
    x2, y2 = Q
    alpha = (y2 - y1) * inv(x2 - x1) % p
    x3 = (B * alpha * alpha - A - x1 - x2) % p
    y3 = (alpha * (x1 - x3) - y1) % p
    return (x3, y3)


def mg_dbl(P):
    x1, y1 = P
    alpha = (3 * x1 * x1 + 2 * A * x1 + 1) * inv(2 * B * y1) % p
    x3 = (B * alpha * alpha - A - 2 * x1) % p
    y3 = (alpha * (x1 - x3) - y1) % p
    return (x3, y3)


def ladder(P, k):
    assert k > 0
    R0 = P
    R1 = mg_dbl(P)
    n = k.bit_length()
    for i in range(n - 2, -1, -1):
        bit = (k >> i) & 1
        if bit == 0:
            R1 = mg_add(R0, R1)
            R0 = mg_dbl(R0)
        else:
            R0 = mg_add(R0, R1)
            R1 = mg_dbl(R1)
    return R0


from sympy.ntheory.residue_ntheory import sqrt_mod

# Recover y for G.x = 9
gx = 9
ysqr = (gx**3 + A * gx * gx + gx) % p
gy = int(sqrt_mod(ysqr, p))
assert (gy * gy) % p == ysqr
G = (gx, gy)

k = 0x1337C0DECAFE
Q = ladder(G, k)
print("Q.x =", Q[0])
