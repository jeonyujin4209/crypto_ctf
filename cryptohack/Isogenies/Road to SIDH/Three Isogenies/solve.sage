"""Three Isogenies (35pts) — 3-isogeny from kernel point K.

E: y^2 = x^3 + x over F_p^2, p = 2^18 * 3^13 - 1.
Kernel K = (483728976, 174842350631).
Flag: j-invariant of codomain.
"""
p = 2^18 * 3^13 - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [1, 0])
K = E(483728976, 174842350631)
print("K order:", K.order())
phi = E.isogeny(K)
E2 = phi.codomain()
print("j(E'):", E2.j_invariant())
