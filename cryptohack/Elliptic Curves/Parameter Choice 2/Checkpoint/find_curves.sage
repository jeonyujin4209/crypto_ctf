"""
Scan b' values for P-256's (p, a) and find prime factors of E.order() in
the tractable range. Output Q points of those orders for oracle PH.

We need product of factors > 2^256 to recover s uniquely.
"""
import json, time

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a_val = p - 3  # NIST P-256 a = -3 mod p

F = GF(p)
a = F(a_val)

LO = 2**15  # min prime factor (brute-forceable)
HI = 2**24  # max prime factor (still brute-forceable)
TARGET_BITS = 270

print(f"[*] Scanning alternative b' for E: y^2 = x^3 + a*x + b' over F_{{p256}}")
print(f"[*] tractable prime range: [2^{LO.nbits()-1}, 2^{HI.nbits()-1}]")

results = []
prod_known = 1
seen_primes = set()

t0 = time.time()
for bp in range(2, 500):
    bp_F = F(bp)
    if bp_F == 0:
        continue
    # Singular check: 4a^3 + 27b^2 != 0
    if 4*a**3 + 27*bp_F**2 == 0:
        continue
    try:
        E = EllipticCurve(F, [a_val, bp])
    except Exception as e:
        continue
    n = E.order()
    fac = list(factor(n))
    # Look for new small primes
    contributed = False
    for (q, e) in fac:
        q = int(q)
        if q < LO or q > HI:
            continue
        if q in seen_primes:
            continue
        # Build a point of order exactly q on E
        cof = n // q
        # Random retry until non-O
        Q = None
        for _try in range(50):
            R = E.random_point()
            T = cof * R
            if T == E(0):
                continue
            if T.order() == q:
                Q = T
                break
        if Q is None:
            continue
        seen_primes.add(q)
        prod_known *= q
        results.append({
            'bp': bp,
            'q': q,
            'Qx': int(Q[0]),
            'Qy': int(Q[1]),
        })
        contributed = True
        print(f"[+] b'={bp}, q={q} ({q.bit_length()}b), prod_bits={prod_known.bit_length()}")
        if prod_known.bit_length() >= TARGET_BITS:
            break
    if prod_known.bit_length() >= TARGET_BITS:
        break

print(f"[*] elapsed {time.time()-t0:.1f}s")
print(f"[*] total prod bits = {prod_known.bit_length()}")
print(f"[*] {len(results)} (b', q, Q) entries")

with open('curves.json', 'w') as f:
    json.dump(results, f)
print("[+] wrote curves.json")
