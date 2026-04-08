#!/usr/bin/env python3
"""
Prime and Prejudice - CryptoHack Challenge Solver
socket.cryptohack.org:13385

Attack: Construct a composite n = p1*p2*p3 that passes Miller-Rabin for all bases < 64.
Set base = p1 (a factor of n), so pow(p1, n-1, n) != 1 (it's 0 mod p1, 1 mod p2*p3 by CRT).
The server returns FLAG[:pow(base, n-1, n)] which gives us the full flag.

Method: Arnault's construction of strong pseudoprimes to fixed bases.
- Choose k values k1=1, k2, k3 (odd) and find p1 such that:
  p_i = k_i * (p1 - 1) + 1 are all prime
  n = p1 * p2 * p3 passes Miller-Rabin for bases 2,3,5,...,61
- Key conditions:
  For each base a < 64, a must be a quadratic non-residue mod each p_i
  (equivalently, Legendre symbol (a/p_i) = -1).
  Then a^((p_i-1)/2) = -1 mod p_i, and the MR witness test is fooled.
  Combined with Korselt-like conditions from the k_i values.

Reference: Arnault (1995), Albrecht et al. "Prime and Prejudice" (2018)
"""

import json
import sys
import itertools
from math import gcd


# =========================================================================
# Miller-Rabin (identical to challenge server)
# =========================================================================
def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if basis[i]:
            basis[i*i::2*i] = [False] * ((n - i*i - 1) // (2*i) + 1)
    return [2] + [i for i in range(3, n, 2) if basis[i]]


def miller_rabin(n, b):
    basis = generate_basis(b)
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for b in basis:
        x = pow(b, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# =========================================================================
# Arnault's construction
# =========================================================================
BASES = generate_basis(64)  # [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]


def legendre(a, p):
    """Compute Legendre symbol (a/p) as 0, 1, or p-1 (representing -1)."""
    return pow(a, (p - 1) // 2, p)


def xgcd(a, b):
    """Extended GCD: returns (gcd, s, t) with a*s + b*t = gcd."""
    s, t, r = 0, 1, b
    s1, t1, r1 = 1, 0, a
    while r != 0:
        q = r1 // r
        r1, r = r, r1 - q * r
        s1, s = s, s1 - q * s
        t1, t = t, t1 - q * t
    return r1, s1, t1


def crt_pair(r1, m1, r2, m2):
    """CRT for two congruences. Returns (residue, modulus) or (-1, -1) if incompatible."""
    g = gcd(m1, m2)
    if r1 % g != r2 % g:
        return -1, -1
    _, s, t = xgcd(m2 // g, m1 // g)
    new_mod = m1 * (m2 // g)
    new_res = (r1 * (m2 // g) * s + r2 * (m1 // g) * t) % new_mod
    return new_res, new_mod


def crt_list(residues, moduli):
    """CRT for a list of congruences."""
    cur_r, cur_m = residues[0], moduli[0]
    for r, m in zip(residues[1:], moduli[1:]):
        cur_r, cur_m = crt_pair(cur_r, cur_m, r, m)
        if cur_r == -1:
            return -1, -1
    return cur_r, cur_m


def compute_S_a(a, search_bound=200):
    """
    For base a, compute S_a: the set of residue classes t mod 4a such that
    Legendre(a, p) = -1 for primes p ≡ t mod 4a.
    We find these by checking small primes.
    """
    S = set()
    for p in generate_basis(search_bound * a)[1:]:  # skip 2 for odd primes
        if legendre(a, p) == p - 1:  # (a/p) = -1
            S.add(p % (4 * a))
    return S


def compute_S_a_prime(S_a, a, ks):
    """
    Compute S_a' = intersection over all k_i of { k_i^{-1} * (S_a + k_i - 1) mod 4a }
    filtered by the constraint that the result ≡ 3 mod 4.
    """
    m = 4 * a
    result = None
    for k in ks:
        k_inv = pow(k, -1, m)
        transformed = set()
        for s in S_a:
            val = ((s + k - 1) * k_inv) % m
            if val % 4 == 3:  # p1 ≡ 3 mod 4 ensures v2(p1-1) = 1
                transformed.add(val)
        if result is None:
            result = transformed
        else:
            result = result.intersection(transformed)
    return result


def find_pseudoprime(ks, target_bits_min=601, target_bits_max=900, max_search=200000):
    """
    Find a strong pseudoprime n = p1 * p2 * ... * ph to all bases < 64.
    p_i = k_i * (p1 - 1) + 1 for the given k values.

    Returns (base, n, factors) or None.
    """
    h = len(ks)
    print(f"[*] Trying k values: {ks}")

    # Step 1: For each base a, compute S_a and then S_a'
    all_S_prime = []
    for a in BASES:
        S_a = compute_S_a(a)
        S_a_p = compute_S_a_prime(S_a, a, ks)
        all_S_prime.append(S_a_p)
        if not S_a_p:
            print(f"    Empty S' for base {a}, these k values won't work")
            return None

    # Print sizes
    total_combos = 1
    for i, S in enumerate(all_S_prime):
        total_combos *= len(S)
    print(f"    Total CRT combinations: {total_combos}")

    # Step 2: Compute Korselt CRT conditions
    # For each k_i (i>0), we need prod_{j!=i}(k_j*(p1-1)+1) ≡ 1 mod k_i
    korselt_residues = []
    korselt_moduli = []

    for i in range(1, h):
        ki = ks[i]
        if ki == 1:
            continue
        valid = []
        for x in range(ki):
            prod_val = 1
            for j in range(h):
                if j != i:
                    prod_val = (prod_val * (ks[j] * (x - 1) + 1)) % ki
            if prod_val % ki == 1:
                valid.append(x)
        if not valid:
            print(f"    No valid p1 mod k{i}={ki} for Korselt, skipping")
            return None
        korselt_residues.append(valid)
        korselt_moduli.append(ki)

    # Step 3: Sample random CRT solutions and search for p1
    import random
    from sympy import isprime

    all_S_lists = [sorted(s) for s in all_S_prime]

    crt_attempts = 0
    max_crt_attempts = min(total_combos, 50000)

    for _ in range(max_crt_attempts):
        # Pick random residue from each S_a'
        tup = [random.choice(lst) for lst in all_S_lists]
        residues = list(tup)
        moduli = [4 * BASES[i] for i in range(len(BASES))]

        # Add Korselt conditions (try each valid residue)
        for kr_list, km in zip(korselt_residues, korselt_moduli):
            residues.append(random.choice(kr_list))
            moduli.append(km)

        sol, modul = crt_list(residues, moduli)
        if sol == -1:
            continue

        crt_attempts += 1
        if crt_attempts % 1000 == 0:
            print(f"    Tried {crt_attempts} valid CRT solutions...")

        # Search for p1 in this residue class, starting from a size that gives 601-900 bit n
        # n ≈ prod(k_i) * p1^h for large p1
        p1_target_bits = target_bits_min // h
        start = 2 ** p1_target_bits + modul  # start above minimum
        offset = (sol - start % modul) % modul
        p1 = start + offset

        for _ in range(max_search // max_crt_attempts + 100):
            if isprime(p1):
                factors = [p1]
                all_prime = True
                for k in ks[1:]:
                    pi = k * (p1 - 1) + 1
                    if not isprime(pi):
                        all_prime = False
                        break
                    factors.append(pi)

                if all_prime:
                    n = 1
                    for f in factors:
                        n *= f
                    if target_bits_min <= n.bit_length() <= target_bits_max:
                        if miller_rabin(n, 64):
                            print(f"\n[+] Found pseudoprime!")
                            print(f"    p1 = {p1}")
                            print(f"    n bits = {n.bit_length()}")
                            print(f"    factors: {len(factors)}")
                            return p1, n, factors

            p1 += modul

    print(f"    Exhausted {crt_attempts} CRT solutions without finding pseudoprime")
    return None


# =========================================================================
# Known working solution (precomputed)
# =========================================================================
def get_known_solution():
    """Return a known working (base, n) pair."""
    p1 = 72728440703025898243229908787433884538071481867621613352800346068965950623818635078553163
    # k values: [1, 101, 73]
    p2 = 101 * (p1 - 1) + 1
    p3 = 73 * (p1 - 1) + 1
    n = p1 * p2 * p3
    return p1, n


# =========================================================================
# Local verification
# =========================================================================
def verify(base, n):
    """Verify all challenge conditions locally."""
    print(f"\n[*] Verification:")
    print(f"    n has {n.bit_length()} bits (need 601-900)")
    print(f"    n > base: {n > base}")

    passes_mr = miller_rabin(n, 64)
    print(f"    Passes MR(64): {passes_mr}")

    x = pow(base, n - 1, n)
    print(f"    pow(base, n-1, n) = {x}")
    print(f"    x >= 50 (enough for flag): {x >= 50}")

    # Check it's actually composite
    print(f"    n is composite: {n % base == 0}")

    # Verify Korselt-like condition
    all_ok = True
    if n.bit_length() < 601 or n.bit_length() > 900:
        all_ok = False
    if not passes_mr:
        all_ok = False
    if x < 50:
        all_ok = False

    return all_ok


# =========================================================================
# Network interaction
# =========================================================================
def solve_remote(base, n):
    """Connect to server and get flag."""
    from pwn import remote

    r = remote("socket.cryptohack.org", 13385)
    r.recvuntil(b"primes!\n")

    payload = json.dumps({"prime": n, "base": base})
    r.sendline(payload.encode())

    response = r.recvline().decode()
    print(f"\n[*] Server response: {response}")
    r.close()
    return response


# =========================================================================
# Main
# =========================================================================
if __name__ == "__main__":
    if "--generate" in sys.argv:
        # Try to generate a new pseudoprime
        # Try several k-value combinations
        k_candidates = [
            [1, 101, 73],
            [1, 73, 101],
            [1, 233, 101],
            [1, 137, 59],
            [1, 89, 73],
        ]
        result = None
        for ks in k_candidates:
            result = find_pseudoprime(ks)
            if result:
                base, n, factors = result
                break

        if result is None:
            print("[!] Generation failed, using known solution")
            base, n = get_known_solution()
        else:
            print(f"\n[+] Generated new pseudoprime with {len(factors)} factors")
    else:
        # Use known working solution
        print("[*] Using known precomputed solution")
        base, n = get_known_solution()

    # Verify
    ok = verify(base, n)
    if not ok:
        print("[!] Verification FAILED!")
        sys.exit(1)
    print("\n[+] All checks passed!")

    # Solve
    if "--remote" in sys.argv:
        print("\n[*] Connecting to server...")
        solve_remote(base, n)
    else:
        print(f"\n[*] Run with --remote to connect to server")
        print(f"[*] Run with --generate to construct a new pseudoprime")
        print(f"\n[*] Payload:")
        print(f'    {{"prime": {n}, "base": {base}}}')
