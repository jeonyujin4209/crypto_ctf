"""CSIDH Key Exchange (90pts) — twist trick, everything over F_p.

Idea: negative step = twist(positive step on twist).
    twist: A ↦ -A (valid when -1 is non-square, which holds for p ≡ 3 mod 4).
So we never need F_p^2 — everything stays in F_p.

Positive step: sample random x in F_p with x^3 + Ax^2 + x a square, lift
to a point P on E, compute the l-isogeny via Sage, extract new A.
"""
from hashlib import sha256
proof.all(False)

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
print("p bits:", p.nbits())
F = GF(p)

a_priv = [-1, -2, -3, -3, -2, -3, -3, 0, 2, -1, 2, -1, -2, -3, 1, 2, 1, 2, 0, 0, 1, -1, 0, 2, -1, 0, 0, 0, 1, -1, -3, 1, -1, -3, -3, 2, 2, 1, -1, -1, 1, 0, 1, 1, 1, -2, 2, 2, -2, -2, 0, 0, 2, 0, -1, -3, -2, -2, 0, -1, -3, -1, -2, -3, -2, 2, 1, 1, -2, 0, 1, -1, -3, 2]
b_priv = [-1, -1, 0, 1, 2, 0, 2, -1, -3, 1, 0, -2, -2, 2, -1, -2, -3, -3, -3, 2, 2, 2, -2, -1, 1, -2, 0, -3, -1, 1, -1, -1, -3, -1, -2, 1, -1, -2, -3, 1, 0, -1, 1, 2, 2, 0, 0, -1, -2, -2, 1, -1, 1, 1, 1, 1, 0, 0, 0, -3, -2, -1, 2, 0, -3, -2, 1, 1, -2, -1, -1, 2, 0, 1]


def curve_from_A(A):
    """Montgomery y^2 = x^3 + A*x^2 + x as Weierstrass over F_p."""
    return EllipticCurve(F, [0, A, 0, 1, 0])


def extract_A(E):
    """Extract Montgomery A from a curve (via Sage's montgomery_model)."""
    Em = E.montgomery_model()
    return Em.a_invariants()[1]


def do_positive_step(A, active_idx_list):
    """Execute all positive l-steps listed in active_idx_list.
    Returns (new_A, remaining_active) where remaining_active contains
    indices that still have work (we may need multiple rounds)."""
    E = curve_from_A(A)
    # Sample point P ∈ E(F_p) (so that the random x gives a quadratic residue)
    for _ in range(100):
        x = F.random_element()
        rhs = x^3 + A*x^2 + x
        if rhs == 0 or not rhs.is_square():
            continue
        P = E.lift_x(x)
        break
    else:
        return A, active_idx_list

    # Multiply by (p+1) / prod(active ells) to project onto the subgroup
    active_ells = [ells[i] for i in active_idx_list]
    cof = (p + 1) // prod(active_ells)
    P = cof * P

    for idx in list(active_idx_list):
        l = ells[idx]
        sub_cof = prod([ells[j] for j in active_idx_list if j != idx])
        K = sub_cof * P
        if K.is_zero() or K.order() != l:
            continue
        phi = E.isogeny(K)
        E_new = phi.codomain()
        P_new = phi(P)
        E = E_new
        P = P_new
        active_idx_list.remove(idx)
        if not active_idx_list:
            break

    return extract_A(E), active_idx_list


def csidh_action(A_start, priv):
    A = F(A_start)
    priv = list(priv)

    while any(e != 0 for e in priv):
        # Positive steps
        pos_active = [i for i in range(len(ells)) if priv[i] > 0]
        if pos_active:
            before = len(pos_active)
            A, remaining = do_positive_step(A, list(pos_active))
            consumed = [i for i in pos_active if i not in remaining]
            for i in consumed:
                priv[i] -= 1

        # Negative steps via twist trick
        neg_active = [i for i in range(len(ells)) if priv[i] < 0]
        if neg_active:
            # Twist: A → -A
            A_twisted = -A
            A_twisted_new, remaining = do_positive_step(A_twisted, list(neg_active))
            # Twist back
            A = -A_twisted_new
            consumed = [i for i in neg_active if i not in remaining]
            for i in consumed:
                priv[i] += 1

    return A


print("[1/3] Alice pub...")
A_alice_pub = csidh_action(0, a_priv)
print(f"  A_alice_pub = {A_alice_pub}")

print("[2/3] Bob pub...")
A_bob_pub = csidh_action(0, b_priv)
print(f"  A_bob_pub = {A_bob_pub}")

print("[3/3] Shared...")
A_s1 = csidh_action(A_bob_pub, a_priv)
A_s2 = csidh_action(A_alice_pub, b_priv)
print(f"  A_s1 = {A_s1}")
print(f"  A_s2 = {A_s2}")
if A_s1 == A_s2:
    print(f"SHARED = {A_s1}")
    print(f"KEY_HEX = {sha256(str(A_s1).encode()).hexdigest()}")
else:
    print("MISMATCH :(")
