"""
Find x0 ∈ Z/(p1*p2) for invalid-curve attack.

mod p1: twist of E has order T1 with smooth part N1 = 1965293129*3945014767*6911909839 (~2^95).
        Pick point P_t1 ∈ E_t(F_p1) of order N1; convert x → x on original E via /d.
mod p2: twist of E has order T2 with smooth part N2 = 17*1789*8984179*9381319*83816652113 (~2^98).
        Same approach.

CRT x0 mod (p1*p2). Submit to server. Save the relevant data for PH.
"""
from sage.all import *
import json

modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
order_subgroup = 4782850957738000717885060297297408935631027604045525430677
a = -3
b = 2697448053935541741976221051345108825177671050689533270507

p1 = 4782850957738000717885060297350722702854694354378697989111
p2 = 4796464665474109238546017500238174976861701183900526078141
assert p1 * p2 == modulus

# Smooth parts of twist orders (from analyze.sage)
N1_factors = [1965293129, 3945014767, 6911909839]
N2_factors = [17, 1789, 8984179, 9381319, 83816652113]

N1 = prod(N1_factors)
N2 = prod(N2_factors)
print(f"N1 = {N1} ({N1.bit_length()} bits)")
print(f"N2 = {N2} ({N2.bit_length()} bits)")
print(f"N1*N2 = {(N1*N2).bit_length()} bits, order needs {order_subgroup.bit_length()} bits")
print()


def setup(p, N_factors):
    """Build E_t over F_p, find P_t of order N=prod(N_factors), return data."""
    F = GF(p)
    E = EllipticCurve(F, [a, b])
    # Find non-residue d
    d = F(2)
    while d.is_square():
        d += 1
    d = ZZ(d)
    print(f"  twist parameter d = {d}")
    # Twist E^d: y² = x³ + a*d²*x + b*d³
    E_t = EllipticCurve(F, [a * d**2, b * d**3])
    T = E_t.order()
    assert T == 2*p + 2 - E.order()
    N = prod(N_factors)
    big = T // N
    print(f"  T_t = {T}")
    print(f"  T/N = {big}")
    # Find P_t of order N
    while True:
        R = E_t.random_point()
        P = big * R
        if P.order() == N:
            break
    x_Et = ZZ(P.xy()[0])
    # Convert to x on E (over F_{p²}): x_E = x_Et / d
    x_E = (x_Et * pow(d, -1, p)) % p
    # Sanity: scalar multiplying x_E via x-only on E with order N should match P scaled.
    return {
        "p": int(p),
        "d": int(d),
        "Et_a": int(a * d**2 % p),
        "Et_b": int(b * d**3 % p),
        "T": int(T),
        "N": int(N),
        "factors": [int(q) for q in N_factors],
        "Pt_x_on_Et": int(x_Et),
        "Pt_y_on_Et": int(P.xy()[1]),
        "x_for_server_mod_p": int(x_E),
    }


print("[*] mod p1 setup...")
data1 = setup(p1, N1_factors)
print(f"   x0 mod p1 = {data1['x_for_server_mod_p']}")
print()

print("[*] mod p2 setup...")
data2 = setup(p2, N2_factors)
print(f"   x0 mod p2 = {data2['x_for_server_mod_p']}")
print()

# CRT combine
x0 = CRT_list([data1['x_for_server_mod_p'], data2['x_for_server_mod_p']], [p1, p2])
x0 = int(x0)
print(f"[*] x0 (mod p1*p2) = {x0}")
print(f"   x0 mod p1 check = {x0 % p1 == data1['x_for_server_mod_p']}")
print(f"   x0 mod p2 check = {x0 % p2 == data2['x_for_server_mod_p']}")

with open('x0_data.json', 'w') as f:
    json.dump({
        "x0": x0,
        "p1": int(p1), "p2": int(p2),
        "data1": data1,
        "data2": data2,
    }, f, indent=2)
print("[+] saved x0_data.json")
