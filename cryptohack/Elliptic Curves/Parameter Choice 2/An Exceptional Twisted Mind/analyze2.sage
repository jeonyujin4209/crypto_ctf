p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
modulus = p^2
order_given = 115792089237316195423570985008687907853233080465625507841270369819257950283813
a = -3
b = 152961

Fp = GF(p)
E_p = EllipticCurve(Fp, [a, b])
N_p = E_p.order()
print("E(F_p).order =", N_p)
print("given order  =", order_given)
print("equal:", N_p == order_given)
print()
print("#E(F_p) == p?  anomalous:", N_p == p)
print("trace:", p + 1 - N_p)
print()
# The modulus is p^2 — maybe the curve is over Z/p^2 for lifting attack?
# Smart/Satoh doesn't care about order structure directly — uses formal log
# to lift the discrete log from F_p to Z_p via Hensel.
