from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

import json
import os

ls = list(primes(3, 112)) + [139]
p = 2 * prod(ls) - 1
max_exp = ceil((sqrt(p) ** (1 / len(ls)) - 1) / 2)
Fp2 = GF(p**2, names="w", modulus=[3, 0, 1])
w = Fp2.gen()
base = EllipticCurve(Fp2, [0, 1])


SECRET = int.from_bytes(os.urandom(8), "big") # 2^64 security is more than enough...
FLAG = b"crypto{????????????????????????????????}"

def encrypt_flag(secret):
    key = SHA256.new(int.to_bytes(int(secret), 8)).digest()[:128]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))

    return iv.hex(), ct.hex()

def private():
    return [randrange(-max_exp, max_exp + 1) for _ in range(len(ls))]

def action(pub, priv):
    E = pub
    es = priv[:]
    while any(es):
        E._order = (p + 1) ** 2  # else sage computes this
        P = E.lift_x(GF(p).random_element())
        s = +1 if P.xy()[1] in GF(p) else -1
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q._order = l  # else sage computes this
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            es[i] -= s
            k //= l
    return E

def backdoor(priv):
    b = 1
    # secret_marks is a redacted CSIDH private key
    for e, m in zip(secret_marks, priv):
        b *= e ^ m
    return b

def package_challenge(EA, EB, EC):
    def package_curve(E):
        return {
            "a4" : list(map(int, E.a4())),
            "a6" : list(map(int, E.a6()))
        }
    return {
        "EA" : package_curve(EA),
        "EB" : package_curve(EB),
        "EC" : package_curve(EC)
    }

def gen_challenge(bit):
    privA = private()
    pubA = action(base, privA)
    privB = private()
    pubB = action(base, privB)
    shared = action(pubB, privA)
    t = backdoor(privA) * backdoor(privB)
    privC = private()
    while backdoor(privC) == t:
        privC = private()
    pubC = action(base, privC)
    if bit:
        return package_challenge(pubA, pubB, shared)
    else:
        return package_challenge(pubA, pubB, pubC)

data = []
for bit in ZZ(SECRET).bits():
    data.append(gen_challenge(bit))

iv, ct = encrypt_flag(SECRET)

output = {}
output["iv"] = iv
output["ct"] = ct
output["challenge_data"] = data 

with open("output.txt", "w") as f:
    f.write(json.dumps(output))
