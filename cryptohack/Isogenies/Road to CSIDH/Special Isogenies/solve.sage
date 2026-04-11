"""Special Isogenies (30pts) — degree-5 isogeny codomain Montgomery A.

E0: y^2 = x^3 + x mod 419. Compute 5-isogeny, convert to Montgomery form.
"""
p = 419
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
print("#E0:", E0.order())

# Try multiple order-5 points to see all distinct codomains
order = E0.order()
cof = order // 5
seen_A = set()
seen_K = []
set_random_seed(42)
for _ in range(100):
    R = E0.random_point()
    K = cof * R
    if K.order() == 5 and K not in seen_K:
        seen_K.append(K)
        phi = E0.isogeny(K)
        E1 = phi.codomain()
        Em = E1.montgomery_model()
        A = Em.a_invariants()
        # Extract A from Montgomery: y^2 = x^3 + Ax^2 + x
        # Sage returns a1,a2,a3,a4,a6 where a2 = A
        print(f"  K={K}, Montgomery A = {A[1]}")
        seen_A.add(A[1])
print("Distinct A values:", seen_A)

phi = E0.isogeny(K)
E1 = phi.codomain()
print("E1 short Weierstrass:", E1)
print("j(E1):", E1.j_invariant())

# Convert to Montgomery form By^2 = x^3 + Ax^2 + x
# Montgomery: j = 256*(A^2 - 3)^3 / (A^2 - 4)
# Given the codomain's j-invariant we can back-solve for A.
# But easier: use Sage's built-in conversion if available.
# Try EllipticCurve.montgomery_model() if available
try:
    Em = E1.montgomery_model()
    print("Montgomery:", Em)
except Exception as e:
    print("no built-in montgomery_model:", e)
    # Manual: given j, solve for A
    j = E1.j_invariant()
    # 256(A^2 - 3)^3 = j*(A^2 - 4)
    R.<A> = PolynomialRing(F)
    poly = 256*(A^2 - 3)^3 - j*(A^2 - 4)
    roots = poly.roots()
    print("possible A values:", roots)
