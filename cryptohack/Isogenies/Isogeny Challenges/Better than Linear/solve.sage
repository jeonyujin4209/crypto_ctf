"""Better than Linear (85pts) — sqrt-speedup isogeny. Sage's isogeny handles
large prime degree via the BDFLS algorithm automatically."""
p = 92935740571
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [1, 0])
K = E(11428792286*i + 6312697112, 78608501229*i + 30552079595)
print("K order:", K.order())
phi = E.isogeny(K, algorithm="factored")
E2 = phi.codomain()
print("j(E'):", E2.j_invariant())
