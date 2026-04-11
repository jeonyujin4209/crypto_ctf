"""Prime Power Isogenies (50pts) — count 7-isogenies to return to start.

Walk 7-isogenies from E0 and count when j-invariant returns to original.
"""
p = 419
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
j0 = E0.j_invariant()

def step_7_positive(E):
    """Take the F_p-rational 7-isogeny. For each cofactor multiple, we get
    a point in the same unique F_p-rational 7-subgroup, so they all give
    the same isogeny (up to isomorphism)."""
    ord_E = E.order()
    cof = ord_E // 7
    for _ in range(200):
        R = E.random_point()
        K = cof * R
        if K.order() == 7:
            return E.isogeny(K).codomain()
    raise RuntimeError("no point")

E = E0
for n in range(1, 80):
    E = step_7_positive(E)
    j = E.j_invariant()
    # Check curve equality (not just j)
    same_curve = (E.a_invariants() == E0.a_invariants())
    is_iso = (j == j0)
    if same_curve:
        print(f"step {n}: j={j} SAME CURVE")
        print(f"\nRETURNED TO START after {n} steps")
        break
    if is_iso:
        print(f"step {n}: j={j} (same j but different curve — isomorphic)")
    else:
        print(f"step {n}: j={j}")
