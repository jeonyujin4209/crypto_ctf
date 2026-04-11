"""
A Twisted Mind — X-only ECDLP via twist + Pohlig-Hellman

The server computes scalarmult(privkey, x0) using an X-only ladder that
doesn't validate x0 is on the curve — so we can supply a point on the
QUADRATIC TWIST. With LIMIT=2 submissions we collect privkey mod a
smooth part of N (curve) and privkey mod a smooth part of N' (twist),
then CRT.

Factorizations (from sympy earlier):
    N  = 2 * 11 * 269 * 2985973 * 1631363213 * 123462957881 * big1
    N' = 2 * 3^3 * 1607 * 693493 * 1483406443 * 40202856427 * big2
Smooth parts: ~102 bits each. CRT combined: 203 bits — covers 191-bit privkey.

Plan (run in two passes — one per submission):
  1. Build curve E and twist Et (twisting by any non-square).
  2. Pick a generator G (curve) of order N. Scale to obtain P = (N / N_smooth)*G,
     so P has order N_smooth. Submit P.x.
  3. Server returns Q.x = (privkey * P).x. Find k such that k*P has x == Q.x,
     via Pohlig-Hellman on each small prime factor.
  4. Repeat on twist with Np_smooth.
  5. CRT combine + sign disambiguation (privkey ∈ [0, order/2]).
"""
from sage.all import *
import json, socket, sys

p  = 2**192 - 237
a  = -3
b  = 1379137549983732744405137513333094987949371790433997718123
N  = 6277101735386680763835789423072729104060819681027498877478
Np = 2*(p+1) - N

F = GF(p)
E = EllipticCurve(F, [a, b])
assert E.order() == N

# Smooth parts we'll recover modulo
N_smooth_factors = [2, 11, 269, 2985973, 1631363213, 123462957881]
# Drop 3^3 (prime-power ambiguity when target order < 27) — use only 3.
Np_smooth_factors = [2, 3, 1607, 693493, 1483406443, 40202856427]

N_smooth = 1
for f in N_smooth_factors:
    N_smooth *= f

Np_smooth = 1
for f in Np_smooth_factors:
    Np_smooth *= f

print(f"[*] N_smooth  = {N_smooth}  ({N_smooth.nbits()} bits)")
print(f"[*] Np_smooth = {Np_smooth}  ({Np_smooth.nbits()} bits)")


# --- Twist curve construction ---
# Quadratic twist of E: E_t: y^2 = x^3 + a*u^2*x + b*u^3 for non-square u
u = F(-1)
while u.is_square():
    u += 1
print(f"[*] twist non-square u = {u}")
Et = EllipticCurve(F, [a * u**2, b * u**3])
assert Et.order() == Np


# --- Build a point P_E on E of order N_smooth ---
print("[*] finding full-order generator G and P_E = cof*G...")
cofactor_E = N // N_smooth
while True:
    G = E.random_point()
    if G.order() == N:  # want G to have full order N
        break
P_E = cofactor_E * G
assert P_E.order() == N_smooth
print(f"[+] P_E = ({P_E[0]}, {P_E[1]})  x0 = {P_E[0]}")

# Build P_Et on Et of order Np_smooth
print("[*] finding G2 (full order Np) and P_Et = cof*G2...")
cofactor_Et = Np // Np_smooth
while True:
    G2 = Et.random_point()
    if G2.order() == Np:
        break
P_Et = cofactor_Et * G2
assert P_Et.order() == Np_smooth
# We need x on E-space, which means mapping Et point to raw x used by server.
# The server's x-only ladder uses x over F_p directly. The twist point (x_t, y_t)
# on Et has y_t^2 = (x_t^3 + a*u^2*x_t + b*u^3). When we feed x = x_t/u to the
# server's ladder on E, the ladder computes k*P where P has x=x_t/u, which lies
# on the twist of E (since (x_t/u)^3 + a*(x_t/u) + b is not a square iff x_t is
# on Et as defined). Actually simpler: for a twist constructed as above,
# x_on_E = x_t / u gives a point on the twist of E when evaluated via the
# x-only ladder. Let me verify by submitting P_Et's x-coord directly and let
# the server's ladder treat it as x-only.
#
# The x-only ladder uses a = -3 and b (from E). If x0 ∉ E (no square root),
# the ladder operates on the twist of E automatically. For our Et constructed
# as [a*u^2, b*u^3], points have x_t = u * X where X is on "twist of E by u".
# So we can submit x = x_t / u to the server.
#
# Actually, the cleanest approach: find twist points of E DIRECTLY (points
# with x such that x^3 - 3x + b is a non-square in F_p). Those lie on the
# twist of E (not on Et explicitly). Then do arithmetic using E's x-ladder.
print(f"[+] P_Et = ({P_Et[0]}, {P_Et[1]})")
# Map to E-twist x-coord: x_on_E_twist = x_t / u
P_Et_x_on_E = F(P_Et[0]) / u
print(f"[+] x0 to submit (twist via E) = {P_Et_x_on_E}")


_p_int = int(p)
_a_int = int(a)
_b_int = int(b)


def _dbl_XZ(P1):
    X1, Z1 = P1
    pL = _p_int; aL = _a_int; bL = _b_int
    XX = (X1 * X1) % pL
    ZZ = (Z1 * Z1) % pL
    A = (2 * ((X1 + Z1) * (X1 + Z1) - XX - ZZ)) % pL
    aZZ = (aL * ZZ) % pL
    X3 = ((XX - aZZ) * (XX - aZZ) - 2 * bL * A * ZZ) % pL
    Z3 = (A * (XX + aZZ) + 4 * bL * ZZ * ZZ) % pL
    return (X3, Z3)


def _diffadd_XZ(P1, P2, x0):
    X1, Z1 = P1
    X2, Z2 = P2
    pL = _p_int; aL = _a_int; bL = _b_int
    X1Z2 = (X1 * Z2) % pL
    X2Z1 = (X2 * Z1) % pL
    Z1Z2 = (Z1 * Z2) % pL
    T = ((X1Z2 + X2Z1) * (X1 * X2 + aL * Z1Z2)) % pL
    Z3 = ((X1Z2 - X2Z1) * (X1Z2 - X2Z1)) % pL
    X3 = (2 * T + 4 * bL * Z1Z2 * Z1Z2 - x0 * Z3) % pL
    return (X3, Z3)


def scalarmult_E_x(k, x0):
    """X-only ladder identical to the server's (works for E and its twist)."""
    k = int(k)
    x0 = int(x0)
    if k == 1:
        return x0
    pL = _p_int
    dbl = _dbl_XZ
    diffadd = _diffadd_XZ
    R0 = (x0, 1)
    R1 = _dbl_XZ(R0)
    n = k.bit_length()
    pbit = 0
    bit = 0
    for i in range(n - 2, -1, -1):
        bit = (k >> i) & 1
        # NOTE: Sage preparser translates `^` to `**`, so we must use `^^`
        # (or int.__xor__) for bitwise XOR.
        pbit = int(pbit).__xor__(int(bit))
        if pbit:
            R0, R1 = R1, R0
        R1 = _diffadd_XZ(R0, R1, x0)
        R0 = _dbl_XZ(R0)
        pbit = bit
    if bit:
        R0 = R1
    if R0[1] == 0:
        return "Infinity"
    return (int(R0[0]) * pow(int(R0[1]), -1, pL)) % pL


# Sanity: verify ladder matches Sage point ops on E
print("[*] sanity check: ladder vs Sage for E")
# Convert all curve params to plain Python ints
p_py = int(p); a_py = int(a); b_py = int(b)
print(f"  p_py = {p_py}")
print(f"  a_py = {a_py}")
print(f"  b_py = {b_py}")

# Inline dbl using plain Python ints
X1 = int(P_E[0])
Z1 = 1
XX = (X1 * X1) % p_py
ZZ = 1
A_coef = (2 * ((X1 + Z1)**2 - XX - ZZ)) % p_py
aZZ = (a_py * ZZ) % p_py
X3 = ((XX - aZZ)**2 - 2 * b_py * A_coef * ZZ) % p_py
Z3 = (A_coef * (XX + aZZ) + 4 * b_py * ZZ**2) % p_py
two_P_x = (X3 * pow(Z3, -1, p_py)) % p_py
print(f"  inline   2P.x = {two_P_x}")
print(f"  Sage     2P.x = {int((2*P_E)[0])}")

# Now test scalarmult_E_x with plain ints
got = scalarmult_E_x(2, int(P_E[0]))
print(f"  ladder 2P.x = {got}")

for k_test in [1, 2, 5, 17, 12345]:
    expected = int((int(k_test) * P_E)[0])
    got = scalarmult_E_x(k_test, int(P_E[0]))
    match = "OK" if expected == got else "MISMATCH"
    print(f"  k={k_test}: sage={expected}  ladder={got}  [{match}]")
print("  E ladder OK")

# Sanity for twist: we feed X_t/u into the ladder and expect (k * P_Et)[0] / u
print("[*] sanity check: ladder vs Sage for twist")
x0_twist = int(F(P_Et[0]) / u)
for k_test in [1, 2, 5, 17, 12345]:
    expected = int(F((k_test * P_Et)[0]) / u)
    got = scalarmult_E_x(k_test, x0_twist)
    assert expected == got, f"twist ladder mismatch at k={k_test}: {expected} vs {got}"
print("  twist ladder OK")


# --- Networking ---
HOST = "socket.cryptohack.org"
PORT = int(13416)  # force plain Python int — Sage preparser would otherwise give Integer


def solve():
    sock = socket.create_connection((HOST, PORT))
    greet = b""
    sock.settimeout(3)
    try:
        while b"\n" not in greet or len(greet) < 50:
            greet += sock.recv(4096)
    except Exception:
        pass
    print(greet.decode(errors='replace'))

    def send(obj):
        sock.send((json.dumps(obj) + "\n").encode())

    def recv():
        buf = b""
        while not buf.endswith(b"\n"):
            c = sock.recv(4096)
            if not c:
                break
            buf += c
        return json.loads(buf.decode())

    # Submission 1: x of P_E (on-curve point of order N_smooth)
    x1 = int(P_E[0])
    send({"option": "get_pubkey", "x0": str(x1)})
    r1 = recv()
    print(f"[1] {r1}")
    Q1_x = int(r1["pubkey"])

    # Submission 2: x of twist point via E's ladder → use P_Et_x_on_E
    x2 = int(P_Et_x_on_E)
    send({"option": "get_pubkey", "x0": str(x2)})
    r2 = recv()
    print(f"[2] {r2}")
    Q2_x = int(r2["pubkey"])

    def dl_in_subgroup(target_x_field, G_sub, f, curve, label=""):
        """Find k ∈ [0, f) such that (k*G_sub).x == target_x_field."""
        try:
            pts = curve.lift_x(target_x_field, all=True)
        except Exception as e:
            print(f"  [{label} f={f}] lift_x failed: {e}")
            return None
        if not pts:
            print(f"  [{label} f={f}] no points with target_x")
            return None
        T = pts[0]
        T_ord = T.order()
        # Normalize T into the order-f subgroup
        if T_ord != f:
            if T_ord % f != 0:
                print(f"  [{label} f={f}] T.order={T_ord} not divisible by f")
                return None
            cof = T_ord // f
            T = cof * T
        try:
            k = discrete_log(T, G_sub, ord=f, operation='+')
            return int(k) % f
        except Exception as e:
            print(f"  [{label} f={f}] discrete_log failed: {e}")
            return None

    # Pohlig-Hellman: for each prime (or prime power) factor f of the
    # smooth subgroup order, compute privkey mod f using:
    #   G_sub = (N_smooth/f) * P_E   (has order f)
    #   Q_sub = (N_smooth/f) * Q     (= privkey * G_sub)
    # Then discrete_log in the order-f subgroup.

    # === Recover privkey mod N_smooth (curve) ===
    print("[*] PH on curve subgroup...")
    residues_E = []
    for f in N_smooth_factors:
        d = N_smooth // f
        G_sub = d * P_E
        assert G_sub.order() == f, f"G_sub order mismatch: {G_sub.order()} vs {f}"
        dQ_x = scalarmult_E_x(d, Q1_x)
        if dQ_x == "Infinity":
            residues_E.append((0, f))
            print(f"  factor {f}: k = 0 (Q·d = O)")
            continue
        target_x = F(dQ_x)
        k = dl_in_subgroup(target_x, G_sub, f, E, label="E")
        print(f"  factor {f}: k = {k}")
        residues_E.append((k, f) if k is not None else None)
    print(f"[*] residues E: {residues_E}")

    # === Recover privkey mod Np_smooth (twist) ===
    print("[*] PH on twist subgroup...")
    residues_Et = []
    for f in Np_smooth_factors:
        d = Np_smooth // f
        G_sub_t = d * P_Et
        assert G_sub_t.order() == f, f"G_sub_t order mismatch: {G_sub_t.order()} vs {f}"
        dQ2_x_on_E = scalarmult_E_x(d, Q2_x)
        if dQ2_x_on_E == "Infinity":
            residues_Et.append((0, f))
            print(f"  factor {f}: k = 0 (Q·d = O)")
            continue
        target_x_Et = F(dQ2_x_on_E) * u
        k = dl_in_subgroup(target_x_Et, G_sub_t, f, Et, label="Et")
        print(f"  factor {f}: k = {k}")
        residues_Et.append((k, f) if k is not None else None)
    print(f"[*] residues Et: {residues_Et}")

    # CRT combine (handle ± ambiguity: try both +k and -k at each step)
    print("[*] CRT combining with sign disambiguation...")
    # There are 2^(number of factors) sign choices. But typically only ± privkey
    # matches overall — so we compute +k vs f-k and pick consistent.
    # Strategy: recover privkey mod 2 from any factor with f=2; use that for sign.
    # Simpler: assume all k's are "aligned" and CRT; if that fails, try flipping.
    from functools import reduce
    def crt_list(pairs):
        """CRT with Chinese remainder over (residue, modulus) pairs."""
        x, m = 0, 1
        for (r, f) in pairs:
            # Merge x mod m with r mod f
            g = gcd(m, f)
            if (r - x) % g != 0:
                return None
            lcm_mf = (m * f) // g
            diff = (r - x) // g
            m_over_g = m // g
            f_over_g = f // g
            inv = pow(m_over_g, -1, f_over_g)
            x = (x + m * ((diff * inv) % f_over_g)) % lcm_mf
            m = lcm_mf
        return x, m

    # Try all sign combinations (2^len)
    from itertools import product
    order_half = N // 2
    all_res = residues_E + residues_Et
    if None in all_res:
        print("[!] some subgroup DL failed")
        return
    for signs in product([1, -1], repeat=len(all_res)):
        pairs = [((s * r) % f, f) for (r, f), s in zip(all_res, signs)]
        result = crt_list(pairs)
        if result is None:
            continue
        x, M = result
        # privkey is in [0, order/2]
        for cand in (x, M - x):
            if 0 < cand <= order_half:
                # Verify by sending as guess
                print(f"  trying privkey = {cand}")
                send({"option": "get_flag", "privkey": str(cand)})
                r3 = recv()
                print(f"  response: {r3}")
                if "flag" in r3:
                    print(f"[+] FLAG = {r3['flag']}")
                    return

    print("[!] exhausted candidates without flag")


solve()
