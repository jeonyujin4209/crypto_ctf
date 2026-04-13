"""Meet me in the Claw - Claw/MITM attack on 2-isogeny graph.

Key insight: Alice's isogeny phi_A is a 2^35-isogeny E0 → EA.
We don't have phiA_P3, phiA_Q3 but we can recover phi_A via
MITM on the j-invariant graph using Phi2 modular polynomial.

Method: DFS from E0 (depth 17) + DFS from EA (depth 18),
match j-invariants, reconstruct path, push P3/Q3 through.
"""
from sage.all import *
from sage.schemes.elliptic_curves.hom_composite import EllipticCurveHom_composite

ea = 35
eb = 29
p = 2**ea * 3**eb - 1

Fp2 = GF(p**2, modulus=[1, 0, 1], name='i')
Fp2_inv_2 = Fp2(1) / 2
(i,) = Fp2.gens()

E0 = EllipticCurve(Fp2, [1, 0])
P2 = E0(1956194174015565770794336*i + 1761758151759977040301838, 2069089015584979134622338*i + 203179590296749797202321)
Q2 = E0(2307879706216488835068177*i + 525239361975369850140518, 1834477572646982833868802*i + 733730165545948547648966)
P3 = E0(2162781291023757368295120*i + 1542032609308508307064948, 1130418491160933565948899*i + 904285233345649302734471)
Q3 = E0(365294178628988623980343*i + 1867216057142335172490873, 2141125983272329025279178*i + 1860108401614981479394873)

EA = EllipticCurve(Fp2, [
    2336060373130772918448023*i + 63223462935813026254900,
    202739861418983960259548*i + 525917254309082638166498
])
sB = 495832856

iv  = bytes.fromhex('9a030e6824e7ec5d66b3443920ea76cb')
ct  = bytes.fromhex('7f11a2ca0359cc5f3a81d5039643b1208ac7eb17f8bd42600d1f67e474cd664dcb8624c94175e167acfe856f48be34bd')


# ─── Helper: sqrt in GF(p^2) ────────────────────────────────────────────────
def sqrt_Fp2(a):
    pp = Fp2.characteristic()
    ii = Fp2.gens()[0]
    a1 = a ** ((pp - 3) // 4)
    x0 = a1 * a
    alpha = a1 * x0
    if alpha == -1:
        return ii * x0
    b = (1 + alpha) ** ((pp - 1) // 2)
    return b * x0


def quadratic_roots(b, c):
    d2 = b**2 - 4*c
    d = sqrt_Fp2(d2)
    return ((-b + d) * Fp2_inv_2, -(b + d) * Fp2_inv_2)


# ─── Modular polynomial Phi_2 neighbors ─────────────────────────────────────
def generic_modular_polynomial_roots(j1):
    R = PolynomialRing(j1.parent(), 'y')
    y = R.gens()[0]
    Phi2 = (
        j1**3 - j1**2*y**2 + 1488*j1**2*y - 162000*j1**2
        + 1488*j1*y**2 + 40773375*j1*y + 8748000000*j1
        + y**3 - 162000*y**2 + 8748000000*y - 157464000000000
    )
    return Phi2.roots(multiplicities=False)


def quadratic_modular_polynomial_roots(jc, jp):
    jc2 = jc**2
    alpha = -jc2 + 1488*jc + jp - 162000
    beta = (jp**2 - jc2*jp + 1488*(jc2 + jc*jp)
            + 40773375*jc - 162000*jp + 8748000000)
    return quadratic_roots(alpha, beta)


def find_j_invs(j1, j_prev=None):
    if j_prev is not None:
        roots = quadratic_modular_polynomial_roots(j1, j_prev)
    else:
        roots = generic_modular_polynomial_roots(j1)
    return [j for j in roots if j != j_prev]


# ─── DFS j-invariant graph ───────────────────────────────────────────────────
def j_invariant_isogeny_graph(j1, e, middle_j_vals=None):
    graph = [{} for _ in range(e + 1)]
    graph[0][j1] = None
    stack = [(j1, 0)]
    while stack:
        node, level = stack.pop()
        parent = graph[level][node]
        child_level = level + 1
        check_middle = (child_level == e) and (middle_j_vals is not None)
        for child in find_j_invs(node, j_prev=parent):
            if child not in graph[child_level]:
                graph[child_level][child] = node
                if check_middle and child in middle_j_vals:
                    return graph, child
                if child_level != e:
                    stack.append((child, child_level))
    return graph, None


def j_invariant_path(graph, j_start, j_end, e, reversed_path=False):
    assert j_start in graph[0]
    assert j_end   in graph[e]
    path = [j_end]
    j = j_end
    for k in reversed(range(1, e + 1)):
        j = graph[k][j]
        path.append(j)
    if not reversed_path:
        path.reverse()
    return path


# ─── Reconstruct isogeny from j-path ────────────────────────────────────────
def generate_kernels_division_polynomial(E, l):
    f  = E.division_polynomial(l)
    xs = [x for x, _ in f.roots()]
    for x in xs:
        K = E.lift_x(x)
        K._order = ZZ(l)
        yield K


def brute_force_isogeny_jinv(E1, j2, l):
    for K in generate_kernels_division_polynomial(E1, l):
        phi = EllipticCurveIsogeny(E1, K, degree=l, check=False)
        if phi.codomain().j_invariant() == j2:
            return phi
    raise ValueError(f"No degree-{l} isogeny found to j={j2}")


def isogeny_from_j_path(E_start, j_path, l):
    assert E_start.j_invariant() == j_path[0]
    factors = []
    E = E_start
    for j_next in j_path[1:]:
        phi = brute_force_isogeny_jinv(E, j_next, l)
        factors.append(phi)
        E = phi.codomain()
    return EllipticCurveHom_composite.from_factors(factors)


# ─── Claw finding ────────────────────────────────────────────────────────────
def claw_finding_attack(E1, E2, l, e):
    e1 = floor(e / 2)
    e2 = e - e1

    j1 = Fp2(E1.j_invariant())
    j2 = Fp2(E2.j_invariant())

    print(f"[*] DFS left  (depth {e1}) ...")
    graph1, _ = j_invariant_isogeny_graph(j1, e1)
    middle = set(graph1[e1].keys())
    print(f"    {len(middle)} middle j-invariants")

    print(f"[*] DFS right (depth {e2}) ...")
    graph2, j_mid = j_invariant_isogeny_graph(j2, e2, middle_j_vals=middle)

    if j_mid is None:
        raise ValueError("No claw found!")
    print(f"[*] Claw found at j_mid = {j_mid}")

    path1 = j_invariant_path(graph1, j1, j_mid, e1)
    path2 = j_invariant_path(graph2, j2, j_mid, e2, reversed_path=True)

    assert path1[-1] == path2[0]
    full_path = path1 + path2[1:]

    print(f"[*] Reconstructing isogeny from {len(full_path)-1}-step path ...")
    phi = isogeny_from_j_path(E1, full_path, l)

    # Fix endpoint with isomorphism
    iso = phi.codomain().isomorphism_to(E2)
    return iso * phi


# ─── Main ────────────────────────────────────────────────────────────────────
print("[*] Running claw-finding attack to recover phi_A: E0 -> EA ...")
phi_A = claw_finding_attack(E0, EA, 2, ea)
print(f"[+] phi_A recovered: {phi_A}")

phiA_P3 = phi_A(P3)
phiA_Q3 = phi_A(Q3)
print(f"[*] phiA_P3 and phiA_Q3 computed")

K_shared = phiA_P3 + sB * phiA_Q3
E_shared = EA.isogeny(K_shared, algorithm="factored").codomain()
j_shared = E_shared.j_invariant()
print(f"[+] shared j = {j_shared}")

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key   = SHA256.new(data=str(j_shared).encode()).digest()[:32]
flag  = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(f"[+] FLAG: {flag.decode()}")
