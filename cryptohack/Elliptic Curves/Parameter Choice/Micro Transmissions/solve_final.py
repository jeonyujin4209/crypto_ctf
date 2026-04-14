"""
Micro Transmissions — Pure Python Pohlig-Hellman solver.
Private key is nbits=64, curve order is smooth -> PH via CRT.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha1

# ── Curve parameters ────────────────────────────────────────────────────────
p  = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a  = 1
b  = 4
Gx = 43190960452218023575787899214023014938926631792651638044680168600989609069200
Gy = 20971936269255296908588589778128791635639992476076894152303569022736123671173
Ax = 87360200456784002948566700858113190957688355783112995047798140117594305287669
Bx = 6082896373499126624029343293750138460137531774473450341235217699497602895121
iv = bytes.fromhex('ceb34a8c174d77136455971f08641cc5')
ct = bytes.fromhex('b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453')

INF = None

def ec_add(P, Q):
    if P is INF: return Q
    if Q is INF: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2:
        if (y1+y2) % p == 0: return INF
        lam = (3*x1*x1 + a) * pow(2*y1, p-2, p) % p
    else:
        lam = (y2-y1) * pow(x2-x1, p-2, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1-x3) - y1) % p
    return (x3, y3)

def ec_mul(P, n):
    if n == 0: return INF
    if n < 0: P = (P[0], (-P[1])%p); n = -n
    R = INF; Q = P
    while n:
        if n & 1: R = ec_add(R, Q)
        Q = ec_add(Q, Q); n >>= 1
    return R

def lift_x(x):
    rhs = (pow(x,3,p) + a*x + b) % p
    y = pow(rhs, (p+1)//4, p)
    assert pow(y,2,p) == rhs, "not QR"
    return (x, y)

def neg_pt(P):
    if P is INF: return INF
    return (P[0], (-P[1])%p)

def bsgs(G_sub, A_sub, l):
    """Find k in [0,l) s.t. k*G_sub == A_sub."""
    if A_sub is INF: return 0
    m = int(l**0.5) + 1
    # Baby steps: full-point key -> j
    baby = {}
    cur = INF
    for j in range(m):
        baby[cur] = j
        cur = ec_add(cur, G_sub)
    # Giant steps
    mG = ec_mul(G_sub, m)
    neg_mG = neg_pt(mG)
    gamma = A_sub
    for i in range(m):
        if gamma in baby:
            k = (i*m + baby[gamma]) % l
            if ec_mul(G_sub, k) == A_sub:
                return k
        neg_g = neg_pt(gamma)
        if neg_g in baby:
            k = (i*m - baby[neg_g]) % l
            if ec_mul(G_sub, k) == A_sub:
                return k
        gamma = ec_add(gamma, neg_mG)
    return None

def crt(rems, mods):
    M = 1
    for m in mods: M *= m
    result = 0
    for r, m in zip(rems, mods):
        Mi = M // m
        result += r * Mi * pow(Mi, -1, m)
    return result % M, M

# Order factorization (from Sage run):
# 7 * 11 * 17 * 191 * 317 * 331 * 5221385621 * 5397618469 * 210071842937040101 * 637807437018177170959577732683
order_factors = [(7,1),(11,1),(17,1),(191,1),(317,1),(331,1),(5221385621,1),(5397618469,1)]
order = 7*11*17*191*317*331*5221385621*5397618469*210071842937040101*637807437018177170959577732683

G = (Gx, Gy)

def try_solve(A, label):
    results, moduli, mul = [], [], 1
    for prime, exp in order_factors:
        pe = prime**exp
        e = order // pe
        G_sub = ec_mul(G, e)
        A_sub = ec_mul(A, e)
        d = bsgs(G_sub, A_sub, pe)
        if d is None:
            print(f"  [{label}] BSGS failed for l={prime}")
            return
        results.append(d)
        moduli.append(pe)
        mul *= pe
        if mul > 2**64:
            break

    n_A, M = crt(results, moduli)
    print(f"  [{label}] n_A = {n_A} ({n_A.bit_length()} bits)")

    # n_A might be M - n_true if lift gave wrong sign
    for n_cand in [n_A, M - n_A]:
        if ec_mul(G, n_cand)[0] == Ax:
            print(f"  [{label}] Verified n_A={n_cand}")
            for Bpt in [lift_x(Bx), neg_pt(lift_x(Bx))]:
                shared = ec_mul(Bpt, n_cand)
                if shared is INF: continue
                key = sha1(str(shared[0]).encode('ascii')).digest()[:16]
                try:
                    flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
                    print(f"  [{label}] FLAG: {flag.decode()}")
                    return
                except Exception:
                    continue
            print(f"  [{label}] decrypt failed")
            return
    print(f"  [{label}] verify failed for both n_A and M-n_A")

A = lift_x(Ax)
print("Trying A (positive lift):")
try_solve(A, "+A")

A_neg = neg_pt(lift_x(Ax))
print("Trying -A (negative lift):")
try_solve(A_neg, "-A")
