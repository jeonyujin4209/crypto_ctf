#!/usr/bin/env python3
"""
Bespoke Padding - CryptoHack RSA PADDING

e=11, custom padding: c = (a*m + b)^11 mod N
Each request returns different random a, b and the ciphertext c.

Attack: Franklin-Reiter related message attack.
With two encryptions:
  c1 = (a1*m + b1)^e mod N
  c2 = (a2*m + b2)^e mod N

Define f1(x) = (a1*x + b1)^e - c1  and  f2(x) = (a2*x + b2)^e - c2 in Z_N[x].
Both have m as a root. So (x - m) divides both.
gcd(f1, f2) in Z_N[x] gives (x - m), revealing m.

Equivalently, substitute y = a1*x + b1:
  g1(y) = y^e - c1
  g2(y) = ((a2*a1_inv)*y + (b2 - a2*a1_inv*b1))^e - c2
Then gcd reveals y - (a1*m + b1), from which m = (y - b1) * a1_inv mod N.

For efficiency with e=11, use polynomial GCD in Z_N[x].
"""

from pwn import *
import json
from Crypto.Util.number import long_to_bytes, GCD

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13386

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def poly_gcd(f, g, N):
    """
    Compute GCD of two polynomials over Z_N.
    Polynomials represented as lists: [a0, a1, ..., an] = a0 + a1*x + ... + an*x^n
    """
    while g and any(c % N for c in g):
        # Make g monic (if leading coeff is invertible mod N)
        if GCD(g[-1], N) != 1:
            # Try swapping
            f, g = g, f
            if GCD(g[-1], N) != 1:
                break
            continue

        lc_inv = pow(g[-1], -1, N)
        g = [(c * lc_inv) % N for c in g]

        # Polynomial division: f = q * g + r
        r = list(f)
        while len(r) >= len(g):
            coeff = r[-1] % N
            for i in range(len(g)):
                r[len(r) - len(g) + i] = (r[len(r) - len(g) + i] - coeff * g[i]) % N
            r.pop()
            # Remove trailing zeros
            while r and r[-1] % N == 0:
                r.pop()

        f, g = g, r

    return f

def poly_mul(f, g, N):
    """Multiply two polynomials mod N."""
    result = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        for j, b in enumerate(g):
            result[i + j] = (result[i + j] + a * b) % N
    return result

def poly_pow_mod(base, exp, mod_poly, N):
    """Compute base^exp mod mod_poly over Z_N."""
    result = [1]  # constant polynomial 1
    base = poly_mod(base, mod_poly, N)
    while exp > 0:
        if exp & 1:
            result = poly_mod(poly_mul(result, base, N), mod_poly, N)
        base = poly_mod(poly_mul(base, base, N), mod_poly, N)
        exp >>= 1
    return result

def poly_mod(f, g, N):
    """Compute f mod g over Z_N."""
    r = list(f)
    if not g or not any(c % N for c in g):
        return r
    lc_inv = pow(g[-1], -1, N)
    while len(r) >= len(g):
        coeff = (r[-1] * lc_inv) % N
        for i in range(len(g)):
            r[len(r) - len(g) + i] = (r[len(r) - len(g) + i] - coeff * g[i]) % N
        r.pop()
        while r and r[-1] % N == 0:
            r.pop()
    return r if r else [0]

def franklin_reiter(e, N, a1, b1, c1, a2, b2, c2):
    """
    Franklin-Reiter related message attack.
    c1 = (a1*m + b1)^e mod N
    c2 = (a2*m + b2)^e mod N
    Returns m.
    """
    # Work with polynomials in Z_N[x]
    # f1(x) = (a1*x + b1)^e - c1
    # f2(x) = (a2*x + b2)^e - c2

    # Build (a1*x + b1)^e using repeated squaring
    # base1 = [b1, a1]  (b1 + a1*x)
    # Need f1 = base1^e - c1

    # For efficiency, compute f1 and f2 directly
    # (a*x + b)^e via binomial theorem
    from math import comb

    def linear_power(a, b, e, N):
        """Compute (a*x + b)^e mod N as polynomial coefficients."""
        coeffs = []
        for k in range(e + 1):
            # coefficient of x^k: C(e,k) * a^k * b^(e-k)
            c = comb(e, k) * pow(a, k, N) % N * pow(b, e - k, N) % N
            coeffs.append(c % N)
        return coeffs

    f1 = linear_power(a1, b1, e, N)
    f1[0] = (f1[0] - c1) % N  # subtract c1

    f2 = linear_power(a2, b2, e, N)
    f2[0] = (f2[0] - c2) % N  # subtract c2

    # Compute GCD
    g = poly_gcd(f1, f2, N)

    if len(g) == 2:
        # g = g[0] + g[1]*x, so root is -g[0]/g[1] mod N
        m = (-g[0] * pow(g[1], -1, N)) % N
        return m
    else:
        log.error(f"GCD degree is {len(g)-1}, expected 1")
        return None

def solve():
    if USE_LOCAL:
        r = process(["python3", "13386_42e6fb9bddd96dc87c9b79435e226329.py"])
    else:
        r = remote(HOST, PORT)

    # Read banner
    r.recvline()

    # Get two encryptions
    resp1 = exchange(r, {"option": "get_flag"})
    c1 = resp1["encrypted_flag"]
    N = resp1["modulus"]
    a1, b1 = resp1["padding"]
    log.info(f"Got encryption 1: a={a1}, b={b1}")

    resp2 = exchange(r, {"option": "get_flag"})
    c2 = resp2["encrypted_flag"]
    a2, b2 = resp2["padding"]
    log.info(f"Got encryption 2: a={a2}, b={b2}")

    assert resp2["modulus"] == N  # same N

    r.close()

    e = 11
    log.info(f"Running Franklin-Reiter attack with e={e}...")
    m = franklin_reiter(e, N, a1, b1, c1, a2, b2, c2)

    if m is not None:
        flag = long_to_bytes(m)
        print(f"Flag: {flag.decode()}")
    else:
        print("Attack failed")

if __name__ == "__main__":
    solve()
