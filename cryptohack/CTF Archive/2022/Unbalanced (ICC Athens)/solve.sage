"""Sage solver for Unbalanced (ICC Athens 2022).

Attack: Trivariate Boneh-Durfee extended with exact constraint y*z = N.
  Polynomial:  f(x, y, z) = 1 + x*(N + 1 - y - z)   (actually writeup uses +2,
  but the key trick is `poly_sub(yz, N)` which reduces mixed y^a z^b monomials).

Unknowns: x = k (~2^300), y = p (~2^256), z = q (~2^768). Root: f(k, p, q) = ed (≡ 0 mod e).

Key insight: use poly_sub to REPLACE every occurrence of y*z with N (exact integer
relation pq = N), which collapses mixed terms and yields tighter Coppersmith bound
than naive bivariate reduction q = N/p.

Reference: https://gist.github.com/maple3142/0bb20789d7372b7e0e822d1b91ca7867
"""
from sage.all import *
import sys
import time

proof.all(False)


def poly_sub(f, x, y):
    """Replace x with y in polynomial f via quotient ring trick."""
    Q = f.parent().quotient(x - y)
    return Q(f).lift()


def main():
    N = 0x7506dad690d57202571d4138e6743e22834072087ef1f81f227409dda108854f2f10c23150dcfbe79940effde0603f64f77f8c123f6ad27ee0ebb3665de8cdb46ced5d2c69f4d9170d406fd93466f8400001b20ea8d084bbb06b28b0ca3782ca2bd92ac012d08103e3477f8ff83c836ebbda570a803bb5b0611b9b285188da53
    e = 0x480fe3b95d6ebadae2a222b6161b8aa0cbb61e0571da3658dac4cf174c7670514c70d8b337408bac467d6a39804efb35394f6d83941fa2d25ca542f630db5b54efaf347062fb828cb7473728de0510f3b27b906c9dd056f77d1ceb0fb249fcc5fe4ee219be82cdb6cee2578b8fa8ad7b489ee45edff4349c4a03af42cc232f65
    c = 0x24581cf0e782e1d6b9d6337e26d87ba16fbf8e5887b83522738769ffa59b38f76eafa61fe9a373948677101f5abe2a4e4032b11ff1c903fe9a0368d07212706bdb4cf24532df6819570ef6935fd3aa5e25f4f65c35a1d6362c8dc3eef95ec15ede94d2acf5ce15cfb81c37bcda4a83660006898f07bf40b072d9382a63b5ab4b

    m, t, a = 5, 5, 0
    bounds = (2**300, 2**256, 2**768)
    R = PolynomialRing(ZZ, ['x', 'y', 'z'])
    x, y, z = R.gens()
    A = N + 1
    f = 2 + x * (A - y - z)  # per writeup; the key is poly_sub below

    print(f"[*] m={m}, t={t}, a={a}", file=sys.stderr)
    polys = Sequence([], R)

    # x-shifts (Boneh-Durfee style)
    for k in range(m):
        for i in range(1, m - k + 1):
            for b in range(2):
                g = e**(m - k) * x**i * y**a * z**b * f**k
                g = poly_sub(g, y * z, N)
                polys.append(g)

    # y-shifts
    for k in range(m + 1):
        for j in range(t + 1):
            h = e**(m - k) * y**(a + j) * f**k
            h = poly_sub(h, y * z, N)
            polys.append(h)

    print(f"[*] {len(polys)} shifts, collecting monomials...", file=sys.stderr)
    B, monomials = polys.coefficients_monomials()
    W = diagonal_matrix([mon(*bounds) for mon in monomials])
    print(f"[*] lattice {B.nrows()}x{B.ncols()}, LLL...", file=sys.stderr)
    t0 = time.time()
    B_red = (B * W).dense_matrix().LLL() / W
    print(f"[*] LLL {time.time() - t0:.1f}s", file=sys.stderr)
    H = list(B_red * monomials)

    p = None
    for i in reversed(range(len(H))):
        try:
            gb = Ideal(H[:i]).groebner_basis()
            roots = gb[0].univariate_polynomial().roots()
            if not roots:
                continue
            p_cand = int(max(roots)[0])
            q_cand = N // p_cand
            if p_cand > 1 and p_cand * q_cand == N:
                p = p_cand
                q = q_cand
                print(f"[+] Factored at subset size {i}", file=sys.stderr)
                break
        except Exception:
            continue

    if p is None:
        print("[-] FAILED", file=sys.stderr)
        sys.exit(1)

    print(f"[+] p = {p}", file=sys.stderr)
    d = int(pow(e, -1, (p - 1) * (q - 1)))
    m_int = int(pow(c, d, N))
    flag = bytes.fromhex(f"{m_int:x}")
    print(flag.decode(errors="replace"))


main()
