"""SIDH Key Exchange (80pts) — full honest SIDH.

We know both secrets sA, sB. Compute:
  - phiA: E0 → EA with kernel <P2 + sA*Q2>, push P3, Q3 through.
  - phiB: E0 → EB with kernel <P3 + sB*Q3>, push P2, Q2 through.
  - phi_SA: EB → ESA with kernel <phiB(P2) + sA*phiB(Q2)>.
  - shared secret = j(ESA).
Then SHA256 it to get AES-CBC key and decrypt flag.
"""
import os
from hashlib import sha256


ea, eb = 110, 67
p = 2**ea * 3**eb - 1
F.<i> = GF(p**2, modulus=[1, 0, 1])
E0 = EllipticCurve(F, [1, 0])

P2 = E0(118242575052254473701407051403380184157502700009529430046122822477*i + 57638278144985143549644316704182130279784191379170896458696787312, 80915735815367072410310689908590367651933218830435520913424043510*i + 35228327576503752484578273317308597612913304063200715424014549037)
Q2 = E0(27856673727210297071672501895829918842041821446996051944738115273*i + 101349537690838191347553037323956940169953967852439843389873653018, 45955772915614774101614751673022340983778200451506382887743008335*i + 76499786039494489791183573966490259392789635716963920208794989512)
P3 = E0(68702305424425607424554396971378391833152415806389206440833676844*i + 63162905189208938201083385603424075109355856156240516441321158383, 14452401602439328239712793251073780692192036710425129093829067649*i + 110903430163815016394569999096524527007769669322432532390635606190)
Q3 = E0(50967992419888058158544483269655763559879646024537212566396940681*i + 39165103284419354968504615023980382940222714919046676966425620242, 113476160032430656302485251779124302915433268423829474022852380544*i + 74814862075401178218909769629701747112662266906635780085603780902)

sA = 225902606209514408534212339057054
sB = 38410379124791756271891302485727


def chain_isogeny(E, K, prime, exponent):
    """Compute the isogeny from E with kernel <K> (order prime^exponent),
    returning (final_E, phi_composed_as_list_of_steps)."""
    steps = []
    E_cur = E
    K_cur = K
    for s in range(exponent):
        sub = K_cur * (prime^(exponent - 1 - s))  # has order `prime`
        phi = E_cur.isogeny(sub)
        E_cur = phi.codomain()
        K_cur = phi(K_cur)
        steps.append(phi)
    return E_cur, steps


def push_through(pt, steps):
    for phi in steps:
        pt = phi(pt)
    return pt


# Bob computes public: E_B and phi_B(P2), phi_B(Q2)
K_B = P3 + sB * Q3
E_B, steps_B = chain_isogeny(E0, K_B, 3, eb)
phiB_P2 = push_through(P2, steps_B)
phiB_Q2 = push_through(Q2, steps_B)
print("E_B j:", E_B.j_invariant())

# Alice computes shared secret: on EB, kernel <phiB(P2) + sA*phiB(Q2)>
K_SA = phiB_P2 + sA * phiB_Q2
E_SA, _ = chain_isogeny(E_B, K_SA, 2, ea)
j_shared = E_SA.j_invariant()
print("shared j(E_SA):", j_shared)

# Decrypt flag via external python (Sage image has no pycryptodome)
print("KEY_HEX:", sha256(str(j_shared).encode()).hexdigest())
