"""
An Exceptional Twisted Mind — Smart attack on E(Z/p^2).

modulus = p^2 with p = 2^256 - 189. |E(F_p)| = order = 256-bit PRIME (no
smooth structure on E or its twist). Standard PH/twist won't work.

Key vulnerability: doing scalar mul on Z/p^2 (composite) means we operate on
E(Z/p^2), whose group order is p · |E(F_p)|. The reduction E(Z/p^2) → E(F_p)
has kernel ≅ (F_p, +) (the formal group). Multiplying any point P_2 ∈ E(Z/p^2)
by N := |E(F_p)| sends it into the kernel, where DLP is trivial (additive).

Recipe:
1. Build P_2 ∈ E(Z/p^2) by Hensel-lifting (x0_F, y0_F) ∈ E(F_p).
2. Submit X0 = x of P_2 to server. Server returns R = x of (k * P_2) mod p^2.
3. Hensel-lift R to (R, Y_R) ∈ E(Z/p^2). Two y choices ⇒ ±k mod p ambiguity.
4. Compute K_P := N * P_2, K_Q := N * Q_2  using full point arithmetic mod p^2
   (Sage's `EllipticCurve(Zmod(p^2), [a,b])` if it works, else hand-coded).
5. Formal log: ψ(K) = -X(K) / Y(K) mod p^2; this is in p · F_p ⇒ divide by p.
6. k mod p = ψ(K_Q) / ψ(K_P) mod p.
7. Two y_R sign options → 2 candidates. Submit each via get_flag.
"""
from sage.all import *
import os, sys, json, socket, time, re

modulus = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
order_subgroup = 115792089237316195423570985008687907853233080465625507841270369819257950283813
a = -3
b = 152961
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
assert p*p == modulus
N = order_subgroup  # = |E(F_p)|

R_p = Zmod(modulus)
F_p = GF(p)


# ---------- BJ x-only mult (mirror of server) ----------
def bj_scalarmult(scalar, x0_in, m=modulus):
    A = a; B = b
    def dbl(P1):
        X1, Z1 = P1
        XX = X1*X1 % m; ZZ = Z1*Z1 % m
        Aa = 2*((X1+Z1)**2 - XX - ZZ) % m
        aZZ = A*ZZ % m
        X3 = ((XX-aZZ)**2 - 2*B*Aa*ZZ) % m
        Z3 = (Aa*(XX+aZZ) + 4*B*ZZ*ZZ) % m
        return (X3, Z3)
    def diffadd(P1, P2, x0_):
        X1, Z1 = P1; X2, Z2 = P2
        X1Z2 = X1*Z2 % m; X2Z1 = X2*Z1 % m; Z1Z2 = Z1*Z2 % m
        T = (X1Z2 + X2Z1)*(X1*X2 + A*Z1Z2) % m
        Z3 = (X1Z2 - X2Z1)**2 % m
        X3 = (2*T + 4*B*Z1Z2*Z1Z2 - x0_*Z3) % m
        return (X3, Z3)
    R0 = (x0_in, 1); R1 = dbl(R0)
    n = scalar.bit_length(); pbit = 0; bit = 0
    for i in range(n-2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0_in)
        R0 = dbl(R0)
        pbit = bit
    if bit:
        R0 = R1
    if gcd(R0[1], m) != 1:
        return "Infinity"
    return int(R0[0]) * pow(int(R0[1]), -1, m) % m


# ---------- Hensel lift y from F_p to Z/p^2 ----------
def hensel_lift_y(X, m=modulus, prime=p):
    """Return list of y in Z/m with y^2 = X^3+a*X+b mod m. 0, 1, or 2 entries."""
    rhs_p2 = (X**3 + a*X + b) % m
    rhs_p = rhs_p2 % prime
    rhs_p_F = F_p(rhs_p)
    if not rhs_p_F.is_square():
        return []
    y_F = rhs_p_F.sqrt()
    out = []
    for y0_F in (y_F, -y_F):
        Y0 = int(y0_F)
        # y = Y0 + p*delta, want y^2 ≡ rhs_p2 mod p^2
        # 2*Y0*p*delta ≡ rhs_p2 - Y0^2 mod p^2
        diff = (rhs_p2 - Y0*Y0) % m
        assert diff % prime == 0
        delta = (diff // prime * pow(2*Y0, -1, prime)) % prime
        Y = (Y0 + prime * delta) % m
        assert (Y*Y - rhs_p2) % m == 0
        out.append(Y)
    return out


# ---------- Hand-coded projective point arithmetic on E(Z/p^2) ----------
# Use Jacobian coords (X, Y, Z) with x = X/Z^2, y = Y/Z^3.
# Identity = (1, 1, 0).

def jac_dbl(P, m=modulus):
    X1, Y1, Z1 = P
    if Z1 == 0:
        return P
    A = X1*X1 % m
    B_ = Y1*Y1 % m
    C = B_*B_ % m
    Z1Z1 = Z1*Z1 % m
    D = 2*((X1 + B_)**2 - A - C) % m
    E_ = 3*A + a*Z1Z1*Z1Z1 % m
    F_ = E_*E_ % m
    X3 = (F_ - 2*D) % m
    Y3 = (E_*(D - X3) - 8*C) % m
    Z3 = ((Y1 + Z1)**2 - B_ - Z1Z1) % m
    return (X3, Y3, Z3)

def jac_add(P, Q, m=modulus):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    if Z1 == 0: return Q
    if Z2 == 0: return P
    Z1Z1 = Z1*Z1 % m
    Z2Z2 = Z2*Z2 % m
    U1 = X1*Z2Z2 % m
    U2 = X2*Z1Z1 % m
    S1 = Y1*Z2*Z2Z2 % m
    S2 = Y2*Z1*Z1Z1 % m
    H = (U2 - U1) % m
    if H == 0:
        if (S2 - S1) % m == 0:
            return jac_dbl(P, m)
        else:
            # Could be inverse, return identity. But on Z/p^2 the "==0" check
            # is mod p^2 — for kernel collisions we won't see this here.
            return (1, 1, 0)
    HH = H*H % m
    HHH = H*HH % m
    r = (S2 - S1) % m
    V = U1*HH % m
    X3 = (r*r - HHH - 2*V) % m
    Y3 = (r*(V - X3) - S1*HHH) % m
    Z3 = Z1*Z2*H % m
    return (X3, Y3, Z3)

def jac_mul(k, P, m=modulus):
    """k*P via double-and-add (left-to-right)."""
    if k == 0:
        return (1, 1, 0)
    if k < 0:
        # negate Y, then mul by |k|
        X, Y, Z = P
        return jac_mul(-k, (X, (-Y) % m, Z), m)
    R = (1, 1, 0)
    for bit in bin(k)[2:]:
        R = jac_dbl(R, m)
        if bit == '1':
            R = jac_add(R, P, m)
    return R

def jac_to_affine(P, m=modulus):
    X, Y, Z = P
    if Z == 0:
        return None  # identity
    # x = X / Z^2, y = Y / Z^3
    Z2 = Z*Z % m
    Z3 = Z2*Z % m
    g = gcd(Z, m)
    if g != 1:
        return ('kernel', X, Y, Z)  # need special handling
    Z2_inv = pow(Z2, -1, m)
    Z3_inv = pow(Z3, -1, m)
    return (X*Z2_inv % m, Y*Z3_inv % m)


# ---------- Formal log on kernel points ----------
def formal_log(P_jac, m=modulus, prime=p):
    """For P in kernel of E(Z/p^2) → E(F_p), return ψ(P) ∈ F_p."""
    X, Y, Z = P_jac
    # Affine x = X/Z^2, y = Y/Z^3.
    # Formal coord: t = -x/y = -X*Z / Y mod m.
    # For kernel elements, t ∈ p·F_p ⇒ divide by p.
    g = gcd(Y, m)
    if g != 1:
        raise RuntimeError(f"formal_log: gcd(Y, m) = {g}, can't invert")
    t_num = (-X*Z) % m
    t_den_inv = pow(Y, -1, m)
    t = t_num * t_den_inv % m
    if t % prime != 0:
        # Not in kernel
        raise RuntimeError(f"formal_log: t mod p = {t % prime} != 0")
    return (t // prime) % prime


def x_from_jac(P_jac, m=modulus, prime=p):
    """For non-kernel P, return affine x mod m. For kernel, return None."""
    X, Y, Z = P_jac
    if gcd(Z, m) != 1:
        return None
    Z2 = Z*Z % m
    return X * pow(Z2, -1, m) % m


# ---------- Choose base point ----------
def make_base_point(seed=None):
    if seed is not None:
        from sage.all import set_random_seed
        set_random_seed(seed)
    # Find x0_F with QR rhs in F_p
    while True:
        x0_F = F_p.random_element()
        if x0_F == 0:
            continue
        if (x0_F**3 + a*x0_F + b).is_square():
            break
    X0 = int(x0_F)
    ys = hensel_lift_y(X0)
    Y0 = ys[0]
    return X0, Y0


# ---------- Recovery from R ----------
def recover_k_mod_p(X0, Y0, R):
    """Given P=(X0,Y0) on Z/p^2 and R = x of (k*P), return list of candidate k mod p."""
    P_jac = (X0, Y0, 1)
    K_P = jac_mul(N, P_jac)
    psi_P = formal_log(K_P)
    if psi_P == 0:
        raise RuntimeError("psi(N*P) = 0; pick different base point")

    candidates = []
    Y_Rs = hensel_lift_y(R)
    if not Y_Rs:
        raise RuntimeError("R not on E(Z/p^2) — twist case unhandled here")
    for Y_R in Y_Rs:
        Q_jac = (R, Y_R, 1)
        K_Q = jac_mul(N, Q_jac)
        psi_Q = formal_log(K_Q)
        k_mod_p = (psi_Q * pow(psi_P, -1, p)) % p
        candidates.append(int(k_mod_p))
    return candidates, int(psi_P)


# ---------- Local test ----------
def local_test():
    raw = int.from_bytes(os.urandom(32), 'big')
    k = min(raw % N, (N - raw) % N)
    print(f"[test] k = {k}")
    X0, Y0 = make_base_point(seed=12345)
    print(f"[test] X0 = {X0}")
    R = bj_scalarmult(k, X0)
    print(f"[test] R = {R}")
    if R == "Infinity":
        print("[test] BJ returned Infinity (k ≡ 0 mod ord(P_F)); rerun")
        return False
    cands, psi_P = recover_k_mod_p(X0, Y0, R)
    print(f"[test] psi(N*P) = {psi_P}")
    print(f"[test] candidates k mod p:")
    for c in cands:
        print(f"  {c}  match={c == k % p}")
    return any(c == k % p for c in cands)


# ---------- Remote ----------
HOST = "socket.cryptohack.org"
PORT = int(13417)


def sock_connect():
    return socket.create_connection((HOST, int(PORT)), timeout=int(15))

def recv_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(8192)
        if not c:
            break
        buf += c
    return buf

def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def remote_attack():
    sock = sock_connect()
    sock.settimeout(3)
    greet = b""
    try:
        while True:
            c = sock.recv(8192)
            if not c:
                break
            greet += c
    except socket.timeout:
        pass
    sock.settimeout(int(15))
    print(greet.decode(errors='replace'))

    X0, Y0 = make_base_point(seed=42)
    print(f"[*] X0 = {X0}")
    send_json(sock, {"option": "get_pubkey", "x0": str(X0)})
    line = recv_line(sock).decode()
    print("[server]", line.strip())
    resp = json.loads(line)
    R = int(resp['pubkey'])
    print(f"[*] R = {R}")

    cands, psi_P = recover_k_mod_p(X0, Y0, R)
    print(f"[*] {len(cands)} formal-log candidates")
    # cand is k mod p (could be true k or -k mod p). Privkey ∈ [0, order/2)
    # is min(k_mod_order, order - k_mod_order). Enumerate all unique guesses
    # mod order: for each cand in {cand1, p - cand1, cand2, p - cand2},
    # try guess = cand mod order and (order - cand mod order) mod order.
    guesses = set()
    for c in cands:
        c = int(c)
        for v in (c, (p - c) % p):
            v_mod = v % N
            guesses.add(int(v_mod))
            guesses.add(int((N - v_mod) % N))
    print(f"[*] {len(guesses)} unique guesses to try")

    for guess in sorted(guesses):
        print(f"[*] trying privkey = {guess}")
        send_json(sock, {"option": "get_flag", "privkey": int(guess)})
        line = recv_line(sock).decode()
        print("[server]", line.strip())
        if 'flag' in line.lower() and 'crypto{' in line:
            break
    sock.close()


import os as _os
mode = _os.environ.get('MODE', 'test')
print(f"[mode] {mode}")
if mode == 'test':
    local_test()
elif mode == 'remote':
    remote_attack()
