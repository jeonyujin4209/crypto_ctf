from sage.all import *

modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
order   = 4782850957738000717885060297297408935631027604045525430677
a = -3
b = 2697448053935541741976221051345108825177671050689533270507

# Known factorization (factordb)
p1 = 4782850957738000717885060297350722702854694354378697989111
p2 = 4796464665474109238546017500238174976861701183900526078141
assert p1 * p2 == modulus
assert is_prime(p1) and is_prime(p2)

print("p1 bits:", p1.bit_length(), "p2 bits:", p2.bit_length())
print("order bits:", order.bit_length(), "is prime:", is_prime(order))
print()

for label, q in [("p1", p1), ("p2", p2)]:
    Fq = GF(q)
    Eq = EllipticCurve(Fq, [a, b])
    Nq = Eq.order()
    Tq = 2*q + 2 - Nq  # quadratic twist order
    print(f"--- mod {label} ({q.bit_length()}b) ---")
    print(f"|E(F_{label})|       = {Nq}")
    print(f"  factor: {factor(Nq)}")
    print(f"|E_twist(F_{label})| = {Tq}")
    print(f"  factor: {factor(Tq)}")
    print(f"  order divides |E|? {Nq % order == 0}")
    print(f"  order divides |T|? {Tq % order == 0}")
    print()
