"""
What a Curve! (Breizh CTF) - Hyperelliptic Jacobian Mumford-coordinate leak

Vulnerability:
  PRNG outputs are FULL Mumford coordinates of points on Jacobian J of a hyperelliptic curve
  C: y^2 = f(x) over GF(p), genus g=7, p≈2^64. Each output exposes (u[0..6], v[0..6]).
  The Mumford constraint v(x)^2 ≡ f(x) (mod u(x)) yields g=7 GF(p)-linear equations on f's
  16 coefficients per leaked point. Three queries (3*7=21 ≥ 16) recover unknown f.

Recovery of the flag:
  First XOR uses seed=2023 (known) but unknown initial point P0. ct1 length is 112 = one full
  update; flag length = 112 - 56 = 56. The known suffix XOR reveals bytes [56,112) = ENTIRE
  v polynomial of `2023*P0`. With v fully known and f recovered, u must be a monic deg-7
  factor of (v^2 - f). Factor over GF(p)[x], enumerate candidate u's, decrypt → flag.

Skills used: hyperelliptic-jacobian-mumford-leak (added).

Usage:
  1. python3 collect.py    # connects to server, dumps session_data.json
  2. sage solve.sage       # runs offline math (or via docker mount)
"""

import json, struct, os

p = 17585255163044402023
R = GF(p)['x']
x = R.gen()

if not os.path.exists("session_data.json"):
    raise SystemExit("Run `python3 collect.py` first to gather session_data.json")

with open("session_data.json") as F:
    data = json.load(F)

queries = [bytes.fromhex(q) for q in data["queries"]]
ct1 = bytes.fromhex(data["ct1"])
print(f"[*] ct1 len: {len(ct1)}")

def parse_uvs(ks):
    vals = struct.unpack('<14Q', ks[:112])
    return list(vals[:7]), list(vals[7:14])

def reduce_xi_mod_u(u_poly, i):
    poly = (R.gen()^i) % u_poly
    return [poly[j] for j in range(7)]

# Step 1: recover f via linear system from queries
rows, rhs = [], []
for q in queries:
    u_c, v_c = parse_uvs(q)
    u_poly = R(u_c + [1])
    v_poly = R(v_c)
    v2_mod_u = (v_poly * v_poly) % u_poly
    M = [reduce_xi_mod_u(u_poly, i) for i in range(16)]
    for j in range(7):
        rows.append([M[i][j] for i in range(16)])
        rhs.append(v2_mod_u[j])

A = Matrix(GF(p), rows)
b = vector(GF(p), rhs)
print(f"[*] linear system {A.dimensions()}, rank {A.rank()}")
f_sol = A.solve_right(b)
f_coeffs = [int(c) for c in f_sol]
f_poly = R(f_coeffs)
print(f"[*] recovered f")

# Step 2: extract v polynomial of `2023*P0` from suffix XOR
suffix = b" This is your final boss, enjoy it while you still can:)"
flag_len = len(ct1) - 56
print(f"[*] flag len = {flag_len}")
assert flag_len >= 0

ks_known = {}
for i in range(flag_len, flag_len+56):
    ks_known[i] = ct1[i] ^^ suffix[i-flag_len]

full_uints = {}
for u_idx in range(14):
    bytes_known = []
    for j in range(8):
        bp = 8*u_idx + j
        if bp in ks_known:
            bytes_known.append((j, ks_known[bp]))
    if len(bytes_known) == 8:
        val = 0
        for off, bv in bytes_known:
            val |= bv << (8*off)
        full_uints[u_idx] = val

assert all(i in full_uints for i in range(7,14)), \
    f"v not fully known (alignment mismatch); flag_len={flag_len}"

v_poly = R([full_uints[7+i] for i in range(7)])
print(f"[*] v(x) recovered")

# Step 3: u is a monic deg-7 factor of (v^2 - f)
target = v_poly^2 - f_poly
fac = list(target.factor())
print(f"[*] (v^2 - f) factor degrees: {[(g.degree(), m) for g,m in fac]}")

candidates = []
def search(idx, deg_left, current):
    if deg_left == 0:
        u_cand = R(1)
        for k, gp in current:
            u_cand *= gp^k
        candidates.append(u_cand.monic())
        return
    if idx >= len(fac):
        return
    gp, m = fac[idx]
    d = gp.degree()
    for k in range(0, m+1):
        if k*d <= deg_left:
            search(idx+1, deg_left - k*d, current + [(k, gp)])
        else:
            break
search(0, 7, [])
print(f"[*] {len(candidates)} candidate u's")

# Step 4: decrypt with each candidate
for u_cand in candidates:
    u_coeffs = [int(u_cand[i]) for i in range(7)]
    if any(c == 0 or c == 1 for c in u_coeffs):
        continue  # original RNG asserts no 0/1 in output uints
    try:
        ks_full = struct.pack('<14Q', *(u_coeffs + [int(v_poly[i]) for i in range(7)]))
    except struct.error:
        continue
    flag_test = bytes(ks_full[i] ^^ ct1[i] for i in range(flag_len))
    if all(32 <= b < 127 for b in flag_test):
        print(f"[+] FLAG: {flag_test.decode()}")
