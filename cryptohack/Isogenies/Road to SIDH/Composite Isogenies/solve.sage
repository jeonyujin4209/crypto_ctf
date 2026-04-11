"""Composite Isogenies (60pts) — chain 13 three-isogenies.

K has order 3^13. We chain 13 three-isogenies. Sage's E.isogeny() accepts
a composite order point IF we pass a list of kernel generators, but the
cleanest way is to walk: scale K to order 3, compute phi_i, push K through.
"""
p = 2^18 * 3^13 - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [1, 0])

Kx = 357834818388*i + 53943911829
Ky = 46334220304*i + 267017462655
K = E(Kx, Ky)
print("K order:", K.order())
assert K.order() == 3^13

E_cur = E
K_cur = K
for step in range(13):
    sub = K_cur * (3^(12 - step))  # has order 3
    phi = E_cur.isogeny(sub)
    E_cur = phi.codomain()
    K_cur = phi(K_cur)
    print(f"  step {step+1}: j = {E_cur.j_invariant()}")

print()
print("final j:", E_cur.j_invariant())
