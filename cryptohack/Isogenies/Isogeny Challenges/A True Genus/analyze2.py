"""
A True Genus - Check genus character Legendre(j(E), p)
and also Legendre(a4, p), Legendre(a6, p).

The genus character for Z[sqrt(-p)] (disc = -4p, p ≡ 1 mod 4)
should be χ(E) = (D / N(ideal)) = (-4p / l_i) for small prime l_i.

But for the challenge data, we try to find what function f(E) satisfies
    f(shared) = f(EA) * f(EB)  for all challenges.
"""
import json
from math import prod

def primes_between(lo, hi):
    sieve = [True] * (hi+1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(hi**0.5)+1):
        if sieve[i]:
            for j in range(i*i, hi+1, i):
                sieve[j] = False
    return [x for x in range(lo, hi+1) if sieve[x]]

ls = primes_between(3, 112) + [139]
p = 2 * prod(ls) - 1
print(f"p bits: {p.bit_length()}, p % 4 = {p % 4}, p % 8 = {p % 8}")
print(f"len(ls) = {len(ls)}")

def legendre(a, l):
    a = a % l
    if a == 0:
        return 0
    return 1 if pow(a, (l-1)//2, l) == 1 else -1

# F_{p^2} element: (a, b) represents a + b*w where w^2 = -3 mod p
def fp2_mul(x, y):
    a1, b1 = x; a2, b2 = y
    return ((a1*a2 - 3*b1*b2) % p, (a1*b2 + a2*b1) % p)
def fp2_add(x, y):
    return ((x[0]+y[0]) % p, (x[1]+y[1]) % p)
def fp2_inv(x):
    a, b = x
    norm = (a*a + 3*b*b) % p
    ni = pow(norm, p-2, p)
    return (a*ni % p, (-b*ni) % p)
def fp2_pow(x, n):
    result = (1, 0)
    base = x
    while n > 0:
        if n & 1:
            result = fp2_mul(result, base)
        base = fp2_mul(base, base)
        n >>= 1
    return result

def j_invariant(a4, a6):
    a4_fp2 = tuple(a4); a6_fp2 = tuple(a6)
    a4_3 = fp2_pow(a4_fp2, 3)
    num4 = fp2_mul((4, 0), a4_3)
    j1728 = fp2_mul((1728, 0), num4)
    a6_2 = fp2_pow(a6_fp2, 2)
    d2 = fp2_mul((27, 0), a6_2)
    denom = fp2_add(num4, d2)
    di = fp2_inv(denom)
    return fp2_mul(j1728, di)

with open(r'C:\Users\UserK\Documents\hackerone\program\crypto_ctf\cryptohack\Isogenies\Isogeny Challenges\A True Genus\output.txt') as f:
    data = json.load(f)
iv = data['iv']; ct = data['ct']
challenges = data['challenge_data']
print(f"Loaded {len(challenges)} challenges")

# Precompute j-invariants
jvals = []
for ch in challenges:
    ja = j_invariant(ch['EA']['a4'], ch['EA']['a6'])
    jb = j_invariant(ch['EB']['a4'], ch['EB']['a6'])
    jc = j_invariant(ch['EC']['a4'], ch['EC']['a6'])
    jvals.append((ja, jb, jc))

print(f"All j in Fp: {all(j[1]==0 for triple in jvals for j in triple)}")
print()

# ── Test 1: Legendre(j, p) ─────────────────────────────────────────────────
print("=== Test 1: f(E) = Legendre(j(E), p) ===")
bits = []
for ja, jb, jc in jvals:
    ga = legendre(int(ja[0]), p)
    gb = legendre(int(jb[0]), p)
    gc = legendre(int(jc[0]), p)
    if ga == 0 or gb == 0 or gc == 0:
        bits.append(None)
    elif gc == ga * gb:
        bits.append(1)
    else:
        bits.append(0)
print(f"  Predictions (first 20): {bits[:20]}")
none_count = bits.count(None)
print(f"  None: {none_count}, 1: {bits.count(1)}, 0: {bits.count(0)}")
print()

# ── Test 2: Legendre(a4[0], p) ────────────────────────────────────────────
print("=== Test 2: f(E) = Legendre(a4[0], p) ===")
bits2 = []
for ch in challenges:
    a4a, a4b, a4c = ch['EA']['a4'][0], ch['EB']['a4'][0], ch['EC']['a4'][0]
    ga = legendre(a4a, p); gb = legendre(a4b, p); gc = legendre(a4c, p)
    if ga==0 or gb==0 or gc==0:
        bits2.append(None)
    elif gc == ga*gb:
        bits2.append(1)
    else:
        bits2.append(0)
print(f"  Predictions (first 20): {bits2[:20]}")
print(f"  None: {bits2.count(None)}, 1: {bits2.count(1)}, 0: {bits2.count(0)}")
print()

# ── Test 3: Legendre(a6[0], p) ────────────────────────────────────────────
print("=== Test 3: f(E) = Legendre(a6[0], p) ===")
bits3 = []
for ch in challenges:
    a6a, a6b, a6c = ch['EA']['a6'][0], ch['EB']['a6'][0], ch['EC']['a6'][0]
    ga = legendre(a6a, p); gb = legendre(a6b, p); gc = legendre(a6c, p)
    if ga==0 or gb==0 or gc==0:
        bits3.append(None)
    elif gc == ga*gb:
        bits3.append(1)
    else:
        bits3.append(0)
print(f"  Predictions (first 20): {bits3[:20]}")
print(f"  None: {bits3.count(None)}, 1: {bits3.count(1)}, 0: {bits3.count(0)}")
print()

# ── Test 4: Legendre(j*j_conj, p) = Legendre(Norm(j), p) ─────────────────
print("=== Test 4: f(E) = Legendre(Norm(j), p) (Norm = a^2 + 3*b^2) ===")
bits4 = []
for ja, jb, jc in jvals:
    def norm_fp2(x):
        a, b = x
        return (a*a + 3*b*b) % p
    ga = legendre(norm_fp2(ja), p)
    gb = legendre(norm_fp2(jb), p)
    gc = legendre(norm_fp2(jc), p)
    if ga==0 or gb==0 or gc==0:
        bits4.append(None)
    elif gc == ga*gb:
        bits4.append(1)
    else:
        bits4.append(0)
print(f"  Predictions (first 20): {bits4[:20]}")
print(f"  None: {bits4.count(None)}, 1: {bits4.count(1)}, 0: {bits4.count(0)}")
print()

# ── Test 5: product of Legendre(j, l) for all l in ls ────────────────────
print("=== Test 5: f(E) = prod(Legendre(j, l_i) for l_i in ls) ===")
bits5 = []
for ja, jb, jc in jvals:
    def char_prod(j):
        r = 1
        for l in ls:
            leg = legendre(int(j[0]), l)
            if leg != 0:
                r *= leg
        return r
    ga = char_prod(ja); gb = char_prod(jb); gc = char_prod(jc)
    if ga==0 or gb==0 or gc==0:
        bits5.append(None)
    elif gc == ga*gb:
        bits5.append(1)
    else:
        bits5.append(0)
print(f"  Predictions (first 20): {bits5[:20]}")
print(f"  None: {bits5.count(None)}, 1: {bits5.count(1)}, 0: {bits5.count(0)}")
print()

# ── Test 6: product of Legendre(-4p, l_i*N) or similar ───────────────────
print("=== Test 6: Direct Kronecker(-4p, j) ===")
D = -4*p
bits6 = []
for ja, jb, jc in jvals:
    def kron(a):
        return legendre(int(a[0]), p)   # simplified
    # Try: f(E) = Kronecker(D, j[0]) = product formula
    # Actually: product over all prime factors of j[0]
    from sympy import factorint
    def kronecker_D_n(n):
        n = n % p
        if n == 0: return 0
        # Kronecker(D, n) = Kronecker(-4p, n)
        # = Kronecker(-1, n) * Kronecker(4, n) * Kronecker(p, n)
        # = (-1)^((n-1)/2) * 1 * Kronecker(p, n)   (since n is odd for n<p)
        # For n even: skip
        if n % 2 == 0: return 0
        sign = (-1) ** ((n-1)//2)
        leg_p_n = legendre(p % n, n)  # Legendre(p, n) by QR
        return sign * leg_p_n
    ga = kronecker_D_n(int(ja[0]))
    gb = kronecker_D_n(int(jb[0]))
    gc = kronecker_D_n(int(jc[0]))
    if ga==0 or gb==0 or gc==0:
        bits6.append(None)
    elif gc == ga*gb:
        bits6.append(1)
    else:
        bits6.append(0)
print(f"  Predictions (first 20): {bits6[:20]}")
print(f"  None: {bits6.count(None)}, 1: {bits6.count(1)}, 0: {bits6.count(0)}")
print()

# ── Which test gives consistent (all 1 or all 0 per challenge) results? ──
print("=== Comparing tests 1-6 ===")
all_tests = [bits, bits2, bits3, bits4, bits5, bits6]
for i in range(min(20, len(challenges))):
    row = [t[i] if i < len(t) else '?' for t in all_tests]
    print(f"  Challenge {i:2d}: {row}")

# Check if any single test gives ALL-consistent predictions
for test_idx, test_bits in enumerate(all_tests):
    if all(b is not None for b in test_bits):
        print(f"\nTest {test_idx+1} has no None values! Bits = {test_bits}")
