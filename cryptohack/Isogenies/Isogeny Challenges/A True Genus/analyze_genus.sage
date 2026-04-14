"""
A True Genus - Empirical analysis of the backdoor structure and genus characters.

Strategy:
1. Reconstruct CSIDH primitives
2. Empirically study what properties of the CURVE correspond to backdoor(priv)
3. Find a genus character computable from the curve alone
"""
import json
from hashlib import sha256

proof.all(False)

ls = list(primes(3, 112)) + [139]
p = 2 * prod(ls) - 1
max_exp = ceil((sqrt(p) ** (1 / len(ls)) - 1) / 2)
Fp2 = GF(p**2, names="w", modulus=[3, 0, 1])
w = Fp2.gen()
Fp = GF(p)
base = EllipticCurve(Fp2, [0, 1])

print(f"p = {p}")
print(f"p.nbits() = {p.nbits()}")
print(f"len(ls) = {len(ls)}")
print(f"max_exp = {max_exp}")
print(f"ls[:5] = {ls[:5]}")
print()

def private():
    return [randrange(-max_exp, max_exp + 1) for _ in range(len(ls))]

def action(pub, priv):
    E = pub
    es = priv[:]
    while any(es):
        E._order = (p + 1) ** 2
        P = E.lift_x(Fp.random_element())
        s = +1 if P.xy()[1] in Fp else -1
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q._order = l
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            es[i] -= s
            k //= l
    return E

# Test: generate a few key pairs and check class group structure
print("=== Generating 3 test key pairs ===")
test_pairs = []
for _ in range(3):
    priv = private()
    pub = action(base, priv)
    test_pairs.append((priv, pub))
    print(f"  priv[:3] = {priv[:3]}..., j(pub) = {pub.j_invariant()}")

print()
print("=== Checking commutativity (CSIDH property) ===")
privA, pubA = test_pairs[0]
privB, pubB = test_pairs[1]
shared1 = action(pubA, privB)
shared2 = action(pubB, privA)
print(f"  action(pubA, privB).j = {shared1.j_invariant()}")
print(f"  action(pubB, privA).j = {shared2.j_invariant()}")
print(f"  Equal: {shared1.j_invariant() == shared2.j_invariant()}")

print()
print("=== Analyzing genus characters ===")
# For each prime l in ls, try: Legendre(j(E)[0], l) as a character
# Hypothesis: genus_l(shared) = genus_l(EA) * genus_l(EB)
def genus_char_j(E, l):
    """Legendre symbol of the 'a' part of j-invariant mod l"""
    j = E.j_invariant()
    # j is in Fp2 = a + b*w; use the trace j + j^p = 2a (trace of j)
    # Actually, j_rational = j[0] (the F_p component when w^2=-3)
    j_list = list(j)
    return kronecker(int(j_list[0]), l)

def genus_char_a4(E, l):
    a4 = E.a4()
    a4_list = list(a4)
    return kronecker(int(a4_list[0]), l)

def genus_char_a6(E, l):
    a6 = E.a6()
    a6_list = list(a6)
    return kronecker(int(a6_list[0]), l)

# Check if Legendre(j(shared)[0], l) == Legendre(j(EA)[0], l) * Legendre(j(EB)[0], l)
print("Checking character multiplicativity for l in ls (first 10):")
for l in ls[:10]:
    g_A = genus_char_j(pubA, l)
    g_B = genus_char_j(pubB, l)
    g_shared = genus_char_j(shared1, l)
    expected = g_A * g_B
    print(f"  l={l}: g(A)={g_A}, g(B)={g_B}, g(shared)={g_shared}, g(A)*g(B)={expected}, match={g_shared==expected}")

print()
# Try with the "norm" j*j^p (N(j) in F_p)
def genus_char_norm_j(E, l):
    j = E.j_invariant()
    norm_j = j * j.frobenius()  # N(j) = j * j^p should be in Fp
    norm_j_fp = Fp(norm_j)
    return kronecker(int(norm_j_fp), l)

print("Checking with Norm(j) character:")
for l in ls[:10]:
    g_A = genus_char_norm_j(pubA, l)
    g_B = genus_char_norm_j(pubB, l)
    g_shared = genus_char_norm_j(shared1, l)
    expected = g_A * g_B
    print(f"  l={l}: g(A)={g_A}, g(B)={g_B}, g(shared)={g_shared}, expected={expected}, match={g_shared==expected}")

print()
print("=== Checking trace character ===")
# trace = j + j^p = 2*j[0] (the real part)
def genus_char_trace_j(E, l):
    j = E.j_invariant()
    trace_j = j + j.frobenius()  # = 2*j[0]
    trace_j_fp = Fp(trace_j / 2)
    return kronecker(int(trace_j_fp), l)

print("Checking with Trace(j)/2 character:")
for l in ls[:10]:
    g_A = genus_char_trace_j(pubA, l)
    g_B = genus_char_trace_j(pubB, l)
    g_shared = genus_char_trace_j(shared1, l)
    expected = g_A * g_B
    print(f"  l={l}: g(A)={g_A}, g(B)={g_B}, g(shared)={g_shared}, expected={expected}, match={g_shared==expected}")
