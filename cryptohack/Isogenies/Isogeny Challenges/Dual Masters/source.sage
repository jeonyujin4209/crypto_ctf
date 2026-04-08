from Crypto.Util.number import bytes_to_long

FLAG = b"crypto{???????????????????????????}"


def gen_pubkey(E, P, Q, Q_other):
    n = bytes_to_long(FLAG[7:-1])
    R = P + n * Q
    phi = E.isogeny(R, algorithm="factored")
    codomain = phi.codomain()
    phi_Q = phi(Q_other)
    return codomain, phi_Q


# Define Curve params
l_a, l_b = 2, 3
e_a = 216
e_b = 137
p = (l_a ^ e_a) * (l_b ^ e_b) - 1
F = GF(p ^ 2, name="i", modulus=[1, 0, 1])
E = EllipticCurve(F, [0, 1])
assert E.order() == ((l_a**e_a) * (l_b**e_b)) ** 2

# Cofactors
c_a = l_b ^ e_b
c_b = l_b ^ e_b

# Compute generators of E[l_a^e_a] and E[l_b^e_b]
P, Q = E.gens()
P_a, Q_a = c_a * P, c_a * Q
print(f"Public parameters:\nE_0 = {E}\nP_a = {P_a}\nQ_a = {Q_a}")

# Generate keypair
E_A, Q_B = gen_pubkey(E, P_a, Q_a, Q_a)

print(f"\nMy fresh, safer, public key:\nE_A = {E_A}\nphi_a(Q_b) = {Q_B}")
