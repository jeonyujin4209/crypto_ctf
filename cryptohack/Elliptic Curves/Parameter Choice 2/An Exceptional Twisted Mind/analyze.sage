from sage.all import *

modulus = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813
a = -3
b = 152961

# factordb confirmed modulus = p^2
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
assert p*p == modulus
print("p bits:", p.bit_length())
print("p == 2^256 - 189?", p == 2**256 - 189)
print("p prime?", is_prime(p))
print()
F = GF(p)
E = EllipticCurve(F, [a, b])
N = E.order()
print("|E(F_p)| =", N)
print("expected order =", order)
print("match?", N == order)
print("|E| prime?", is_prime(N))
print()
t = p + 1 - N
print("trace t =", t)
print("|E_twist(F_p)| =", 2*p + 2 - N)
print("|E_twist| factors:", factor(2*p + 2 - N))
