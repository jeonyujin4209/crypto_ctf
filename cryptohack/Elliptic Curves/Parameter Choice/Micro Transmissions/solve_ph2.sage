"""Micro Transmissions — simplified PH (no bounds shenanigans)."""
from hashlib import sha1

p  = 99061670249353652702595159229088680425828208953931838069069584252923270946291
ax = 87360200456784002948566700858113190957688355783112995047798140117594305287669
bx = 6082896373499126624029343293750138460137531774473450341235217699497602895121

E = EllipticCurve(GF(p), [1, 4])
G = E.gens()[0]
order = E.order()
print(f"[*] E.order() = {order}")
print(f"[*] factorization:", factor(order))

# Just ask Sage: given A = n*G, find n.
# Use global discrete_log with ord = order. Sage's PH kicks in automatically
# and should complete in seconds because the small factors are small.

# Try both lifts of A
A_ref = E.lift_x(GF(p)(ax))
B = E.lift_x(GF(p)(bx))

for A_sign_label, A in [("+A", A_ref), ("-A", -A_ref)]:
    print(f"\n=== {A_sign_label} ===")
    try:
        n_a = int(discrete_log(A, G, ord=order, operation='+'))
        print(f"  n_a = {n_a}")
        print(f"  bits = {n_a.bit_length()}")
        print(f"  verify n_a*G == A: {n_a*G == A}")
        # Also check n_a mod 2^64 — in case discrete_log returns a larger value
        n_cand = n_a % (2^64)
        print(f"  n_a mod 2^64 = {n_cand}")
        print(f"  verify: {n_cand*G == A}")
        if n_a * G == A or n_cand * G == A:
            shared = int((min(n_a, n_cand) * B).xy()[0])
            print(f"  shared = {shared}")
            print(f"  KEY = {sha1(str(shared).encode()).hexdigest()}")
            break
    except Exception as ex:
        print(f"  failed: {ex}")
