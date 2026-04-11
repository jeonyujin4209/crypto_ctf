"""Two Isogenies (30pts) — compute 2-isogeny via E.isogeny(K).

E: y^2 = x^3 + x over F_p^2, p = 2^18 * 3^13 - 1.
Kernel: K = (i, 0).
Flag: j-invariant of the codomain.
"""
p = 2^18 * 3^13 - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [1, 0])
K = E(i, 0)
phi = E.isogeny(K)
E2 = phi.codomain()
print("E' order:", E2.order())
print("j(E'):", E2.j_invariant())
