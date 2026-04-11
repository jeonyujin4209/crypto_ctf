"""Meet me in the Claw — MITM claw attack on the 2-isogeny graph.

Alice's secret phi_A is a 2^35-isogeny from E_0 to E_A. It corresponds to
a path of length 35 in the supersingular 2-isogeny graph. We BFS from
both E_0 (depth 17) and E_A (depth 18), match on j-invariants.
Then reconstruct the path → phi_A → push P_3, Q_3 through → combine with
sB to compute shared secret → decrypt flag.
"""
from hashlib import sha256
import os
proof.all(False)

ea = 35
eb = 29
p = 2^ea * 3^eb - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E0 = EllipticCurve(F, [1, 0])

P2 = E0(1956194174015565770794336*i + 1761758151759977040301838,
        2069089015584979134622338*i + 203179590296749797202321)
Q2 = E0(2307879706216488835068177*i + 525239361975369850140518,
        1834477572646982833868802*i + 733730165545948547648966)
P3 = E0(2162781291023757368295120*i + 1542032609308508307064948,
        1130418491160933565948899*i + 904285233345649302734471)
Q3 = E0(365294178628988623980343*i + 1867216057142335172490873,
        2141125983272329025279178*i + 1860108401614981479394873)

EA = EllipticCurve(F, [
    2336060373130772918448023*i + 63223462935813026254900,
    202739861418983960259548*i + 525917254309082638166498
])

sB = 495832856

# Ciphertext from README
iv_hex = '9a030e6824e7ec5d66b3443920ea76cb'
ct_hex = '7f11a2ca0359cc5f3a81d5039643b1208ac7eb17f8bd42600d1f67e474cd664dcb8624c94175e167acfe856f48be34bd'


def neighbors_2iso(E):
    """Return list of (phi, E_next) for all 2-isogenies from E."""
    # E[2] = points of order dividing 2 (4 points including O)
    order_2_pts = [P for P in E(0).division_points(2) if P.order() == 2]
    result = []
    for P in order_2_pts:
        try:
            phi = E.isogeny(P)
            result.append((phi, phi.codomain()))
        except Exception:
            pass
    return result


# ============ PHASE 1: BFS from E_0 ============
# visited: dict j_invariant → (parent_j, phi_from_parent)
d_left = 17
d_right = ea - d_left  # = 18

print(f"[*] BFS left (depth {d_left}) from E_0 ...")
visited_left = {E0.j_invariant(): (None, None, E0)}  # j → (parent_j, phi, curve)
frontier = [(E0.j_invariant(), E0)]
for step in range(d_left):
    new_frontier = []
    for (j_cur, E_cur) in frontier:
        for phi, E_next in neighbors_2iso(E_cur):
            j_next = E_next.j_invariant()
            if j_next not in visited_left:
                visited_left[j_next] = (j_cur, phi, E_next)
                new_frontier.append((j_next, E_next))
    frontier = new_frontier
    print(f"  step {step+1}: frontier size {len(frontier)}, total visited {len(visited_left)}")

# ============ PHASE 2: BFS from E_A ============
print(f"[*] BFS right (depth {d_right}) from E_A ...")
visited_right = {EA.j_invariant(): (None, None, EA)}
frontier = [(EA.j_invariant(), EA)]
match_j = None
for step in range(d_right):
    new_frontier = []
    for (j_cur, E_cur) in frontier:
        for phi, E_next in neighbors_2iso(E_cur):
            j_next = E_next.j_invariant()
            if j_next not in visited_right:
                visited_right[j_next] = (j_cur, phi, E_next)
                new_frontier.append((j_next, E_next))
                if j_next in visited_left:
                    match_j = j_next
                    print(f"  MATCH at step {step+1}: j = {j_next}")
                    break
        if match_j is not None:
            break
    if match_j is not None:
        break
    frontier = new_frontier
    print(f"  step {step+1}: frontier size {len(frontier)}, total visited {len(visited_right)}")

if match_j is None:
    print("[!] no match found in BFS")
    exit()

# ============ Reconstruct full isogeny chain E_0 → E_A ============
print(f"[*] reconstructing path through j = {match_j}")

def trace_back(visited, j_start):
    path = []
    j = j_start
    while visited[j][0] is not None:
        parent_j, phi, E_cur = visited[j]
        path.append(phi)
        j = parent_j
    return path[::-1]  # E_0 → ... → match


chain_left = trace_back(visited_left, match_j)
chain_right_rev = trace_back(visited_right, match_j)  # E_A → ... → match, we need reverse
# Dual the chain: each phi in chain_right_rev has codomain closer to match
# We need E_match → E_A, which is the reverse path with duals
chain_right = [phi.dual() for phi in chain_right_rev[::-1]]

print(f"[*] left chain: {len(chain_left)} isogenies")
print(f"[*] right chain: {len(chain_right)} isogenies")

# Full phi_A : E_0 → E_A = compose all
def apply_chain(chain, point):
    for phi in chain:
        point = phi(point)
    return point


print(f"[*] pushing P_3, Q_3 through full chain...")
phiA_P3 = apply_chain(chain_left + chain_right, P3)
phiA_Q3 = apply_chain(chain_left + chain_right, Q3)
print(f"    phiA_P3.curve() = {phiA_P3.curve() if hasattr(phiA_P3, 'curve') else 'n/a'}")

# Now use Bob's secret to compute shared
K_SA = phiA_P3 + sB * phiA_Q3
print(f"[*] computing final isogeny on E_A with kernel K_SA")

def composite_3iso(E, K, e):
    for s in range(e):
        sub = K * (3^(e - 1 - s))
        phi = E.isogeny(sub)
        E = phi.codomain()
        K = phi(K)
    return E


E_AB = composite_3iso(EA, K_SA, eb)
j_shared = E_AB.j_invariant()
print(f"[+] shared j = {j_shared}")

key = sha256(str(j_shared).encode()).digest()[:32]
print(f"[+] KEY = {key.hex()}")
