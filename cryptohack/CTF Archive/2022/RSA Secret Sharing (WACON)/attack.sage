"""Sage attack for RSA Secret Sharing (WACON 2022).

Reads from stdin: q, n1, n2, n3, n4 (each on its own line).
Writes to stdout: 8 prime factors p_0, p_1, ..., p_7 (each on its own line),
where n_k = p_{2k} * p_{2k+1}.

Attack premise: user sends LCG1 = (a=1, x=1, b=1) so L1_i = 1+i (the roll index).
Then:
  n_k mod q = (1+r_a)(1+r_b)      — small integer → factor → recover roll indices
  n_k mod q^2 gives B_k = (L2_a*(1+r_b) + L2_b*(1+r_a)) mod q
  4 B_k equations + LCG2 recurrence L2_i = α a_2^i + β → solve a_2 via polynomial root-finding
  Then each prime has p mod q^2 known (684 bits of 1026) → Coppersmith small_roots
"""
from sage.all import *
from itertools import product
import sys
import time


def factor_pairs(n, limit):
    pairs = []
    u = 1
    while u * u <= n and u <= limit:
        if n % u == 0:
            pairs.append((u, n // u))
        u += 1
    return pairs


def recover_index_candidates(q, ns, max_r):
    cands = []
    for n in ns:
        A = int(n) % int(q)
        pairs = factor_pairs(A, limit=max_r)
        valid = [(u - 1, v - 1) for u, v in pairs if u - 1 >= 0 and v - 1 <= max_r]
        cands.append(valid)
    results = []
    for c0, c1, c2, c3 in product(*cands):
        rs = [c0[0], c0[1], c1[0], c1[1], c2[0], c2[1], c3[0], c3[1]]
        if all(rs[i] < rs[i + 1] for i in range(7)):
            results.append(rs)
    return results


def solve_lcg2(q, rs, Bs):
    Fq = GF(q)
    R = PolynomialRing(Fq, 'x')
    x = R.gen()

    f = []
    d = []
    B_F = []
    for k in range(4):
        r_a, r_b = rs[2*k], rs[2*k+1]
        fk = (1 + r_b) * x**r_a + (1 + r_a) * x**r_b
        dk = Fq(r_a + r_b + 2)
        f.append(fk)
        d.append(dk)
        B_F.append(Fq(Bs[k]))

    P012 = (f[0] * (d[1] * B_F[2] - d[2] * B_F[1]) +
            f[1] * (d[2] * B_F[0] - d[0] * B_F[2]) +
            f[2] * (d[0] * B_F[1] - d[1] * B_F[0]))
    P013 = (f[0] * (d[1] * B_F[3] - d[3] * B_F[1]) +
            f[1] * (d[3] * B_F[0] - d[0] * B_F[3]) +
            f[3] * (d[0] * B_F[1] - d[1] * B_F[0]))

    G = gcd(P012, P013)
    if G.degree() < 1:
        return None
    roots = G.roots(ring=Fq, multiplicities=False)

    for a_cand in roots:
        if a_cand == 0 or a_cand == 1:
            continue
        A_mat = Matrix(Fq, [[f[0](a_cand), d[0]], [f[1](a_cand), d[1]]])
        if A_mat.determinant() == 0:
            continue
        sol = A_mat.solve_right(vector(Fq, [B_F[0], B_F[1]]))
        alpha, beta = sol
        ok = True
        for k in range(4):
            lhs = alpha * f[k](a_cand) + beta * d[k]
            if lhs != B_F[k]:
                ok = False
                break
        if ok:
            return int(a_cand), int(alpha), int(beta)
    return None


def coppersmith_factor(N, q, r, L2, epsilon=0.02):
    M = L2 * q + (1 + r)
    R = Zmod(N)
    PR = PolynomialRing(R, 'y')
    y = PR.gen()
    q_inv = inverse_mod(int(q) * int(q), int(N))
    f = y + M * q_inv
    try:
        roots = f.small_roots(X=int(q), beta=0.5, epsilon=epsilon)
    except Exception:
        return None
    for k in roots:
        p_cand = int(M + int(q) * int(q) * int(k))
        if p_cand > 1 and int(N) % p_cand == 0:
            return p_cand
    return None


def attack(q, ns):
    cands = recover_index_candidates(q, ns, max_r=10**5)
    sys.stderr.write(f"[attack] {len(cands)} index candidates\n")

    for c_idx, rs in enumerate(cands):
        Bs = []
        ok = True
        for k in range(4):
            A_k = (1 + rs[2*k]) * (1 + rs[2*k+1])
            residue_q2 = int(ns[k]) % (int(q)**2)
            diff = residue_q2 - A_k
            if diff % int(q) != 0:
                ok = False
                break
            Bs.append(diff // int(q))
        if not ok:
            continue

        result = solve_lcg2(q, rs, Bs)
        if result is None:
            continue
        a_2, alpha, beta = result
        sys.stderr.write(f"[attack] candidate {c_idx} LCG2 solved: a_2 recovered\n")

        L2_rec = [(alpha * pow(a_2, r, int(q)) + beta) % int(q) for r in rs]

        ps = []
        found_all = True
        for k in range(4):
            r_a, r_b = rs[2*k], rs[2*k+1]
            L2_a, L2_b = L2_rec[2*k], L2_rec[2*k+1]
            p = coppersmith_factor(ns[k], q, r_a, L2_a)
            if p is None:
                p = coppersmith_factor(ns[k], q, r_b, L2_b)
            if p is None:
                found_all = False
                break
            pp = int(ns[k]) // p
            ps.extend([p, pp])
        if found_all:
            return ps

    return None


def main():
    lines = sys.stdin.read().strip().split()
    q = int(lines[0])
    ns = [int(x) for x in lines[1:5]]
    t0 = time.time()
    ps = attack(q, ns)
    sys.stderr.write(f"[attack] total {time.time()-t0:.2f}s\n")
    if ps is None:
        sys.stderr.write("[attack] FAILED\n")
        sys.exit(1)
    for p in ps:
        print(p)


main()
