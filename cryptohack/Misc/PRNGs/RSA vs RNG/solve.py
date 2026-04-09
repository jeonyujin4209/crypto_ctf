import json
from math import isqrt
from Crypto.Util.number import long_to_bytes

with open('flag.enc') as f:
    data = json.load(f)
N = data['N']
E = data['E']
ct = int(data['ciphertext'], 16)

MOD = 2**512
A = 2287734286973265697461282233387562018856392913150345266314910637176078653625724467256102550998312362508228015051719939419898647553300561119192412962471189
B = 4179258870716283142348328372614541634061596292364078137966699610370755625435095397634562220121158928642693078147104418972353427207082297056885055545010537

# LCG: state_{n+1} = A*state_n + B mod 2^512
# P and Q are LCG states (both prime), with gap states between them.
# N = P*Q, solve quadratic: A^gap * P^2 + S_gap * P - N = 0 (mod 2^512)
# Use Hensel lifting for even gaps (parity constraint).

for gap in range(2, 1002, 2):
    Ag = pow(A, gap, MOD)
    Sg = 0
    Ai = 1
    for i in range(gap):
        Sg = (Sg + Ai * B) % MOD
        Ai = (Ai * A) % MOD

    # f(P) = Ag*P^2 + Sg*P - N = 0 mod 2^512
    if (Ag + Sg - N) % 2 != 0:
        continue

    candidates = [1]
    failed = False
    for bit in range(1, 512):
        mod = 1 << (bit + 1)
        new_cands = []
        for p in candidates:
            for hb in [0, 1]:
                c = p + hb * (1 << bit)
                if (Ag * c * c + Sg * c - N) % mod == 0:
                    new_cands.append(c)
        candidates = new_cands
        if not candidates:
            failed = True
            break
        if len(candidates) > 100:
            failed = True
            break

    if failed:
        continue

    for p in candidates:
        if p > 1 and N % p == 0:
            Q = N // p
            phi = (p-1)*(Q-1)
            d = pow(E, -1, phi)
            pt = pow(ct, d, N)
            print(f'gap={gap}: {long_to_bytes(pt)}')
            exit()
# crypto{pseudorandom_shamir_adleman}
