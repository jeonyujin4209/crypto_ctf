from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

from os import urandom

FLAG = b"crypto{????????????????????????????????????????????????}"

def dual(phi):
    # Returns the dual up to isomorphism
    l, e = factor(phi.degree())[0]
    E = phi.domain()
    P, Q = E.torsion_basis(l^e)

    K = phi(P)
    if K.order() != phi.degree():
        K = phi(Q)
    assert K.order() == phi.degree(), "Isogeny is not cyclic, of prime power degree"

    phi_hat = phi.codomain().isogeny(K, algorithm="factored")
    phi_hat = phi_hat.codomain().isomorphism_to(E) * phi_hat

    return phi_hat


def gen_pubkey(G, le):
    E = G.curve()
    P, Q = E.torsion_basis(le)

    R = P + randint(0,le)*Q
    phi = E.isogeny(R, algorithm="factored")
    phi_hat = dual(phi)

    return (phi, phi_hat), phi_hat(phi(G))


def derive_secret(sk, G):
    return sk[1](sk[0](G))


def encrypt_flag(shared_secret):
    key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))

    return iv.hex(), ct.hex()


if __name__=="__main__":
    proof.all(False)
    q = 66755491218549620204451278063200785887258235588279474221852899550437797658031
    l_a = 2
    l_b = 3
    e_a = 216
    e_b = 137
    p = (l_a^e_a)*(l_b^e_b)*q - 1
    assert is_pseudoprime(p)
    assert is_pseudoprime(q)

    F2.<i> = GF(p^2, name="i", modulus=x^2 + 1)
    E = EllipticCurve(F2, [1, 0])

    assert E.order() == ((l_a^e_a)*(l_b^e_b)*q)^2

    G = E.random_point()*(l_a^e_a)*(l_b^e_b)

    print(f"Public parameters:\nG = {G.xy()}")

    # Generate keypair
    sk_A, G_A = gen_pubkey(G, l_a^e_a)
    sk_B, G_B = gen_pubkey(G, l_b^e_b)

    print(f"\nPublic keys:\nG_A = {G_A.xy()}\nG_B = {G_B.xy()}")

    ss_A = derive_secret(sk_A, G_B)
    ss_B = derive_secret(sk_B, G_A)

    assert ss_A == ss_B

    iv, ct = encrypt_flag(ss_A)
    print(f"\n\nEncrypted flag: iv = {iv}, ct = {ct}")

