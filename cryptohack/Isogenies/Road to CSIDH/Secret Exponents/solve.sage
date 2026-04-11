"""Secret Exponents (60pts) — CSIDH group action with exponent vector [2,3,4].

Compute degree-3^2 * 5^3 * 7^4 isogeny starting from E0: y^2 = x^3 + x mod 419.
For each prime l with exponent e, walk e steps via l-isogenies using an
F_p-rational point of order l.
"""
p = 419
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
print("#E0:", E0.order())

# Odd primes dividing p+1 = 420 = 2^2 * 3 * 5 * 7 → odd primes: 3, 5, 7
primes = [3, 5, 7]
exponents = [2, 3, 4]

def walk_isogenies(E, l, e):
    """Apply e l-isogenies, picking rational l-torsion point at each step."""
    for step in range(e):
        ord_E = E.order()
        # We need an l-torsion F_p-rational point. CSIDH's positive action
        # uses points of order l over F_p (not twist).
        assert ord_E % l == 0
        cof = ord_E // l
        for _ in range(200):
            R = E.random_point()
            K = cof * R
            if K.order() == l:
                break
        else:
            raise RuntimeError(f"could not find {l}-torsion point")
        phi = E.isogeny(K)
        E = phi.codomain()
    return E

E = E0
for l, e in zip(primes, exponents):
    E = walk_isogenies(E, l, e)
    print(f"  after walking {l}^{e}: {E}")

Em = E.montgomery_model()
A = Em.a_invariants()[1]
print(f"\nMontgomery A = {A}")
