"""Twisted CSIDH Isogenies — walk ONE step backwards on the 3-isogeny graph.

From Prime Power Isogenies, the 3-isogeny graph has some cycle length n.
Walking k-1 forward = walking 1 backward. Or: do it directly via twist.

Approach: compute the full forward 3-isogeny cycle from E0. One step
"backwards" is the second-to-last j (or first element in the reversed walk).

Or more directly: take the twist E^t, walk one 3-isogeny forward there,
then untwist. For simplicity we do the "k-1 forward steps" approach,
using the cycle length detected automatically.
"""
p = 419
F = GF(p)
E0 = EllipticCurve(F, [0, 1, 0, 1, 0])  # Montgomery y^2 = x^3 + 0*x^2 + x ?
# Actually source uses y^2 = x^3 + x which is Montgomery with A=0.
# In Sage Weierstrass: [a1, a2, a3, a4, a6] = [0, 0, 0, 1, 0]
E0_W = EllipticCurve(F, [1, 0])
j0 = E0_W.j_invariant()
print(f"j0 = {j0}")

def step_3_forward(E):
    ord_E = E.order()
    cof = ord_E // 3
    for _ in range(500):
        R = E.random_point()
        K = cof * R
        if K.order() == 3:
            return E.isogeny(K).codomain()
    raise RuntimeError("no 3-point")

# Compute full 3-isogeny cycle
E = E0_W
j_list = [j0]
for n in range(1, 50):
    E = step_3_forward(E)
    j = E.j_invariant()
    j_list.append(j)
    if j == j0:
        print(f"Cycle length = {n}, full j's: {j_list}")
        break

# One backward = take (cycle_len - 1) forward steps from E0
cycle_len = len(j_list) - 1  # j_list[0] = j_list[-1] = j0
print(f"\nCycle length: {cycle_len}")

E = E0_W
for n in range(cycle_len - 1):
    E = step_3_forward(E)
print(f"Curve after {cycle_len-1} forward steps:")
print(f"j = {E.j_invariant()}")
Em = E.montgomery_model()
print(f"Backward Montgomery: {Em}")
print(f"Montgomery A = {Em.a_invariants()[1]}")
