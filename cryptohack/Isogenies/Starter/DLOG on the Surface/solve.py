"""
DLOG on the Surface: 2-dimensional discrete log on E: y^2 = x^3 + x over F_{p^2}
with p = 2^127 - 1, modulus x^2 + 1.

Approach: use Weil pairing + Pohlig-Hellman (bit-by-bit, order = 2^127).

Since E is supersingular, the Weil pairing on E[p+1] is non-degenerate. With
(P, Q) a basis for E[p+1] (Z/(p+1))^2, writing R = aP + bQ, S = cP + dQ:

    e(P, R) = e(P, Q)^b
    e(Q, R) = e(Q, P)^a = e(P, Q)^{-a}
    e(P, S) = e(P, Q)^d
    e(Q, S) = e(P, Q)^{-c}

Then compute a, b, c, d via 2-adic discrete log (bit-by-bit).
"""
import sys, os, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.setrecursionlimit(10000)

p = 2**127 - 1
N = p + 1  # = 2^127 (power of 2)
assert N == 2**127

# F_{p^2} = F_p[i] / (i^2 + 1)
# Element: (a, b) represents a + b*i
def fp2_add(x, y):
    return ((x[0] + y[0]) % p, (x[1] + y[1]) % p)

def fp2_sub(x, y):
    return ((x[0] - y[0]) % p, (x[1] - y[1]) % p)

def fp2_neg(x):
    return ((-x[0]) % p, (-x[1]) % p)

def fp2_mul(x, y):
    # (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    a, b = x
    c, d = y
    return ((a * c - b * d) % p, (a * d + b * c) % p)

def fp2_inv(x):
    a, b = x
    denom = (a * a + b * b) % p
    inv = pow(denom, -1, p)
    return ((a * inv) % p, ((-b) * inv) % p)

def fp2_eq(x, y):
    return x[0] % p == y[0] % p and x[1] % p == y[1] % p

def fp2_from_int(n):
    return (n % p, 0)

def fp2_pow(x, e):
    r = (1, 0)
    base = x
    while e > 0:
        if e & 1:
            r = fp2_mul(r, base)
        base = fp2_mul(base, base)
        e >>= 1
    return r

ZERO = (0, 0)
ONE = (1, 0)

# Curve y^2 = x^3 + x: a = 1, b = 0
A_coef = fp2_from_int(1)
B_coef = fp2_from_int(0)

# Points are either None (infinity) or (x, y)
INF = None

def ec_add(P, Q):
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if fp2_eq(x1, x2):
        if fp2_eq(y1, fp2_neg(y2)):
            return INF
        # doubling: slope = (3 x1^2 + A) / (2 y1)
        num = fp2_add(fp2_mul(fp2_from_int(3), fp2_mul(x1, x1)), A_coef)
        den = fp2_mul(fp2_from_int(2), y1)
        m = fp2_mul(num, fp2_inv(den))
    else:
        num = fp2_sub(y2, y1)
        den = fp2_sub(x2, x1)
        m = fp2_mul(num, fp2_inv(den))
    x3 = fp2_sub(fp2_sub(fp2_mul(m, m), x1), x2)
    y3 = fp2_sub(fp2_mul(m, fp2_sub(x1, x3)), y1)
    return (x3, y3)

def ec_neg(P):
    if P is INF:
        return INF
    return (P[0], fp2_neg(P[1]))

def ec_mul(k, P):
    if k == 0 or P is INF:
        return INF
    if k < 0:
        return ec_mul(-k, ec_neg(P))
    R = INF
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        k >>= 1
    return R

# --- Weil pairing via Miller's algorithm ---
# Miller line function l_{R1, R2}(S) over short Weierstrass:
#   If R1 == -R2 (vertical): l = (S.x - R1.x)
#   If R1 != R2: slope lambda = (y2-y1)/(x2-x1), l = (S.y - y1) - lambda*(S.x - x1)
#   Doubling (R1 == R2): lambda = (3 x1^2 + A)/(2 y1), l = (S.y - y1) - lambda*(S.x - x1)
# Return the value (an F_{p^2} element).
def line(R1, R2, S):
    if R1 is INF or R2 is INF or S is INF:
        return ONE  # treated as 1 if undefined
    x1, y1 = R1
    x2, y2 = R2
    xS, yS = S
    if fp2_eq(x1, x2):
        if fp2_eq(y1, fp2_neg(y2)):
            # vertical line
            return fp2_sub(xS, x1)
        # doubling
        num = fp2_add(fp2_mul(fp2_from_int(3), fp2_mul(x1, x1)), A_coef)
        den = fp2_mul(fp2_from_int(2), y1)
        lam = fp2_mul(num, fp2_inv(den))
    else:
        num = fp2_sub(y2, y1)
        den = fp2_sub(x2, x1)
        lam = fp2_mul(num, fp2_inv(den))
    # l(S) = (yS - y1) - lam*(xS - x1)
    res = fp2_sub(fp2_sub(yS, y1), fp2_mul(lam, fp2_sub(xS, x1)))
    return res

def miller(P, Q, m):
    """
    Miller's algorithm: compute f_{m, P}(Q), where f satisfies div(f) = m*(P) - ([m]P) - (m-1)*(O).
    """
    if P is INF:
        return ONE
    T = P
    f = ONE
    bits = bin(m)[2:]
    for b in bits[1:]:
        # double
        f = fp2_mul(fp2_mul(f, f), line(T, T, Q))
        T2 = ec_add(T, T)
        # divide by vertical line through T2 (which has x = T2.x)
        if T2 is not INF:
            vx = fp2_sub(Q[0], T2[0])
            f = fp2_mul(f, fp2_inv(vx))
        T = T2
        if b == '1':
            f = fp2_mul(f, line(T, P, Q))
            T_new = ec_add(T, P)
            if T_new is not INF:
                vx = fp2_sub(Q[0], T_new[0])
                f = fp2_mul(f, fp2_inv(vx))
            T = T_new
    return f

def weil_pairing(P, Q, m):
    """
    Weil pairing: e_m(P, Q) = (-1)^m * f_P(Q) / f_Q(P).
    For m = 2^k, (-1)^m = 1.
    """
    # The classical definition uses an auxiliary point to avoid div-by-zero,
    # but since we normalize vertical lines above, and P != Q, this usually works.
    fPQ = miller(P, Q, m)
    fQP = miller(Q, P, m)
    res = fp2_mul(fPQ, fp2_inv(fQP))
    # for even m, (-1)^m = 1
    return res

# Alternative: Tate pairing gives same discrete log info and is simpler.
# But Weil pairing works here with order m = N = 2^127.

# Parse points from output.txt
P = (
    (62223422355562631021732597235582046928, 24722427318870186874942502106037863239),
    (149178354082347398743922440593055790802, 66881667812593541117238448140445071224),
)
Q = (
    (52082760150043245190232762320312239515, 136066972787979381470429160016223396048),
    (89777436105166947842660822806860901885, 37290474751398918861353632929218878189),
)
R = (
    (158874018596958922133589852067300239562, 115434063687215369570994517493754451626),
    (81253318200557694469168638082106161224, 62259011436032820287439957155108559928),
)
S = (
    (113049342376647649006990912915011269440, 42595488035799156418773068781330714859),
    (125117346805247292256813555413193592812, 25404988689109287499485677343768857329),
)

iv = bytes.fromhex('6f5a901b9dc00aded4add3791812883b')
ct = bytes.fromhex('56ecb68a90cad9787a24a4511720d40d625901577f6d0f1eef9fc34cf042709110cdc061fff91e934877674a30ed911283b83927dbcc270ae358d6b1fe2d5bed18ce1b02d8805de55e5b36deb0d28883')

# Sanity check: P on E
def on_curve(P):
    if P is INF:
        return True
    x, y = P
    lhs = fp2_mul(y, y)
    rhs = fp2_add(fp2_mul(fp2_mul(x, x), x), x)
    return fp2_eq(lhs, rhs)

for name, Pt in [("P", P), ("Q", Q), ("R", R), ("S", S)]:
    print(f"{name} on curve: {on_curve(Pt)}")

# Sanity: N * P = O
print("N*P =", ec_mul(N, P))
print("N*Q =", ec_mul(N, Q))

# Compute pairings
print("Computing e(P, Q) ...")
ePQ = weil_pairing(P, Q, N)
print(f"e(P, Q) = {ePQ}")

# Check e(P, Q)^N == 1
check = fp2_pow(ePQ, N)
print(f"e(P,Q)^N = {check} (should be (1,0))")

print("Computing e(P, R) ...")
ePR = weil_pairing(P, R, N)
print("Computing e(Q, R) ...")
eQR = weil_pairing(Q, R, N)
print("Computing e(P, S) ...")
ePS = weil_pairing(P, S, N)
print("Computing e(Q, S) ...")
eQS = weil_pairing(Q, S, N)

# 2-adic discrete log: given h = g^x mod ... where g has order 2^127, find x.
# Pohlig-Hellman for 2-power order.
def dlog_2power(g, h, k):
    """
    Find x s.t. g^x = h, where g has order 2^k, 0 <= x < 2^k. O(k^2) multiplications.
    We maintain h_cur = g^{-partial_x} * h incrementally so each step only needs
    one extra multiply plus squarings.
    Algorithm: at step i, let y = h_cur^{2^{k-1-i}}. If y = 1, bit_i = 0. Else bit_i = 1,
    and then we need to multiply h_cur by g^{-2^i}. Precompute g^{2^i}.
    """
    # Precompute g^{2^i} for i in 0..k-1
    gpow = [g]
    for _ in range(k - 1):
        gpow.append(fp2_mul(gpow[-1], gpow[-1]))
    g_half = gpow[-1]  # g^{2^{k-1}} has order 2
    x = 0
    h_cur = h
    for i in range(k):
        # Square h_cur (k-1-i) times
        y = h_cur
        for _ in range(k - 1 - i):
            y = fp2_mul(y, y)
        if fp2_eq(y, (1, 0)):
            bit = 0
        else:
            if not fp2_eq(y, g_half):
                raise ValueError(f"Not a power of g at i={i}")
            bit = 1
            # multiply h_cur by g^{-2^i}: i.e., inv(gpow[i])
            h_cur = fp2_mul(h_cur, fp2_inv(gpow[i]))
        x += bit * (2 ** i)
    return x

print("\nComputing discrete logs (this might take a while)...")
# b = dlog(e(P,R), e(P,Q))
# a = -dlog(e(Q,R), e(P,Q))  [since e(Q,R)=e(P,Q)^(-a)]
# d = dlog(e(P,S), e(P,Q))
# c = -dlog(e(Q,S), e(P,Q))

k = 127

print("Computing b ...")
b = dlog_2power(ePQ, ePR, k)
print(f"b = {b}")

print("Computing a ...")
a_neg = dlog_2power(ePQ, eQR, k)
a = (-a_neg) % N
print(f"a = {a}")

print("Computing d ...")
d = dlog_2power(ePQ, ePS, k)
print(f"d = {d}")

print("Computing c ...")
c_neg = dlog_2power(ePQ, eQS, k)
c = (-c_neg) % N
print(f"c = {c}")

# Verify R = a P + b Q, S = c P + d Q
R_check = ec_add(ec_mul(a, P), ec_mul(b, Q))
print(f"R check: {R_check == R}")
S_check = ec_add(ec_mul(c, P), ec_mul(d, Q))
print(f"S check: {S_check == S}")

# The flag was generated with a, b, c, d all odd (via | 1 in sage).
# They are unique mod N = 2^127.
# Decrypt flag
from Crypto.Hash import SHA256
data_abcd = f"{a}{b}{c}{d}".encode()
key = SHA256.new(data=data_abcd).digest()[:128]  # truncated to 128 bytes? SHA256 gives 32 bytes.
# The script does .digest()[:128] which gives all 32 bytes. AES requires 16/24/32 bytes.
# With a 32-byte key, AES-256.
print(f"key length: {len(key)}")
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
try:
    pt = unpad(pt, 16)
except Exception as e:
    print(f"unpad failed: {e}")
print(f"flag: {pt}")
