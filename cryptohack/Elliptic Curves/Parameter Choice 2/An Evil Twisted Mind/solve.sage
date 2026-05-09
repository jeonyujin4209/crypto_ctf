"""
An Evil Twisted Mind — invalid-curve attack on x-only Brier-Joye scalarmult
where the modulus is composite (p1*p2).

Vulnerability: scalarmult uses only (modulus, a, b) — no on-curve check, and
modulus = p1*p2 (CRT). By choosing x0 such that x0³+a*x0+b is non-residue mod
each pi, the implicit point lives in E_t(F_pi)-component (twist) with smooth
order N_i. PH on each smooth subgroup → k mod N_i; CRT → k mod (N1*N2).

Sign ambiguity per subgroup (x-only ⇒ ±k mod q). Iterate signs and verify
locally by running scalarmult(K, x0) ≡ R (mod modulus).

Final: privkey = min(K mod order, order - K mod order); submit get_flag.
"""
from sage.all import *
import json, socket, sys, time, re
from itertools import product as iproduct

modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
order_subgroup = 4782850957738000717885060297297408935631027604045525430677
a = -3
b = 2697448053935541741976221051345108825177671050689533270507

with open('x0_data.json') as f:
    DATA = json.load(f)

p1 = DATA['p1']; p2 = DATA['p2']; x0 = DATA['x0']
data1 = DATA['data1']; data2 = DATA['data2']


# ------- Brier-Joye scalar mult (mirrors server) -------
def server_scalarmult(scalar, x0_in, m=modulus):
    A_const = a; B_const = b
    def dbl(P1):
        X1, Z1 = P1
        XX = X1*X1 % m
        ZZ = Z1*Z1 % m
        A = 2 * ((X1 + Z1)**2 - XX - ZZ) % m
        aZZ = A_const * ZZ % m
        X3 = ((XX - aZZ)**2 - 2*B_const*A*ZZ) % m
        Z3 = (A * (XX + aZZ) + 4*B_const*ZZ*ZZ) % m
        return (X3, Z3)
    def diffadd(P1, P2, x0_):
        X1, Z1 = P1; X2, Z2 = P2
        X1Z2 = X1*Z2 % m
        X2Z1 = X2*Z1 % m
        Z1Z2 = Z1*Z2 % m
        T = (X1Z2 + X2Z1) * (X1*X2 + A_const*Z1Z2) % m
        Z3 = (X1Z2 - X2Z1)**2 % m
        X3 = (2*T + 4*B_const*Z1Z2*Z1Z2 - x0_*Z3) % m
        return (X3, Z3)
    R0 = (x0_in, 1)
    R1 = dbl(R0)
    n = scalar.bit_length()
    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^^ bit  # XOR in sage syntax
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0_in)
        R0 = dbl(R0)
        pbit = bit
    if bit:
        R0 = R1
    return int(R0[0]) * pow(int(R0[1]), -1, m) % m


# ------- PH per prime side -------
def setup_side(p, dat):
    """Return (E_t, P_t (point of order N), DL precomputation per factor)."""
    F = GF(p)
    E_t = EllipticCurve(F, [dat['Et_a'], dat['Et_b']])
    Pt = E_t(dat['Pt_x_on_Et'], dat['Pt_y_on_Et'])
    N = dat['N']
    assert Pt.order() == N
    bases = []
    for q in dat['factors']:
        Pq = (N // q) * Pt
        assert Pq.order() == q
        bases.append((q, Pq))
    return F, E_t, Pt, bases


def recover_residues_mod_p(p, dat, R_mod_p):
    """Lift R to E_t (one of two y), do PH per factor q, return [(q, k_q ± sign)]."""
    F, E_t, Pt, bases = setup_side(p, dat)
    d = dat['d']
    # R_mod_p is x on E. Convert to x on E_t: x_Et = R_mod_p * d
    x_Et = (R_mod_p * d) % p
    # Lift to E_t (pick one y; sign ambiguity remains)
    Q_lifts = E_t.lift_x(F(x_Et), all=True)
    if not Q_lifts:
        # Should not happen — by construction R_mod_p arose from a twist point.
        raise RuntimeError(f"R_mod_p not on E_t mod {p}")
    Q = Q_lifts[0]
    # Q already lies in the N-subgroup: it's ±(k * P_t) by construction
    # (its x equals x of k*P_t). Don't multiply by cofactor again.
    residues = []
    N = dat['N']
    for q, Pq in bases:
        Q_q = (N // q) * Q  # project into order-q subgroup
        if Q_q.is_zero():
            # k ≡ 0 mod q
            residues.append((q, 0))
            continue
        kq = discrete_log(Q_q, Pq, ord=q, operation='+')
        residues.append((q, int(kq)))
    return residues


def crt_with_signs(residues_signs):
    """Given [(q, r)], return k mod prod(q)."""
    rs = [r for (q, r) in residues_signs]
    qs = [q for (q, r) in residues_signs]
    return int(CRT_list(rs, qs)), int(prod(qs))


# ------- main: drives PH + CRT + sign iteration -------
def recover_k(R):
    R_p1 = R % p1
    R_p2 = R % p2
    print(f"[*] PH mod p1 ({len(data1['factors'])} factors)...")
    res1 = recover_residues_mod_p(p1, data1, R_p1)
    print("   ", res1)
    print(f"[*] PH mod p2 ({len(data2['factors'])} factors)...")
    res2 = recover_residues_mod_p(p2, data2, R_p2)
    print("   ", res2)

    all_res = res1 + res2  # list of (q, k mod q with possibly wrong sign)
    n = len(all_res)
    # Within each side, the sign is coupled: 4 valid combos total
    # (p1±, p2±). Try each by negating residues per side.
    n1 = len(res1); n2 = len(res2)
    print(f"[*] Trying 4 valid sign combos (per-side)...")
    t0 = time.time()
    matches = []
    for s1 in (1, -1):
        for s2 in (1, -1):
            rs = []
            for (q, r) in res1:
                rs.append((q, (s1 * r) % q))
            for (q, r) in res2:
                rs.append((q, (s2 * r) % q))
            K, _ = crt_with_signs(rs)
            Rcand = server_scalarmult(K, x0)
            print(f"   s1={s1:+d} s2={s2:+d}  K={K}  match={Rcand==R}")
            if Rcand == R:
                matches.append(K)
    print(f"   [+] {len(matches)} match(es) in {time.time()-t0:.1f}s")
    return matches


# ------- test mode -------
def local_test():
    """Pick random k, simulate server, attempt recovery."""
    import os
    raw = int.from_bytes(os.urandom(24), 'big')
    k = min(raw % order_subgroup, (order_subgroup - raw) % order_subgroup)
    print(f"[test] privkey k = {k}")
    R = server_scalarmult(k, x0)
    print(f"[test] R = {R}")
    matches = recover_k(R)
    if not matches:
        print("[test] FAIL")
        return False
    print(f"[test] {len(matches)} candidate K values")
    candidates = set()
    for K in matches:
        cand = K % order_subgroup
        cand_min = min(cand, (order_subgroup - cand) % order_subgroup)
        candidates.add(cand_min)
    print(f"[test] {len(candidates)} distinct candidates after mod-order + min-flip")
    found = k in candidates
    print(f"[test] true k in candidates: {found}")
    return found


# ------- remote -------
HOST = "socket.cryptohack.org"
PORT = int(13418)


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
    sock.settimeout(15)
    print(greet.decode(errors='replace'))

    print(f"[*] sending x0 = {x0}")
    send_json(sock, {"option": "get_pubkey", "x0": str(x0)})
    line = recv_line(sock).decode()
    print("[server]", line.strip())
    resp = json.loads(line)
    R = int(resp['pubkey'])
    print(f"[*] R = {R}")

    matches = recover_k(R)
    if not matches:
        print("[!] no recovery")
        sock.close()
        return
    candidates = set()
    for K in matches:
        cand = K % order_subgroup
        cand_min = min(cand, (order_subgroup - cand) % order_subgroup)
        candidates.add(int(cand_min))
    print(f"[*] {len(candidates)} candidates to try")

    for cand_min in sorted(candidates):
        print(f"[*] trying privkey = {cand_min}")
        send_json(sock, {"option": "get_flag", "privkey": cand_min})
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
