"""sage script: LLL/BKZ to find collision message m with M(m) ≡ M_target mod N.
Input: reads p, M_TARGET, PRE from stdin or hard-coded via args.
"""
import sys
import json

PRE = int.from_bytes(b'SECUREHASH_', 'big')
TARGET = b'pleasegivemetheflag'
M_TARGET = int.from_bytes(b'SECUREHASH_' + TARGET, 'big')

# Read p from args
p = int(sys.argv[1])
N = p - 1
B = 256

def find_collision(L, center=12, width=13, block_size=20, W_scale=1):
    """Try to find m of length L with given character range [0x61, 0x7a].
    y_i = x_i - center, y_i in [-center, width-1]."""
    A_sum = 0x61 * (B**L - 1) // (B - 1)
    shift_sum = center * (B**L - 1) // (B - 1)
    D = (M_TARGET - PRE * B**L - A_sum) % N
    E = (D - shift_sum) % N

    coefs = [B**(L-1-i) for i in range(L)]
    W = N * W_scale
    K = 1

    M = matrix(ZZ, L+2, L+2)
    for i in range(L):
        M[i, i] = 1
        M[i, L] = coefs[i] * W
    M[L, L] = N * W
    M[L+1, L] = E * W
    M[L+1, L+1] = K

    print(f'  BKZ(bs={block_size}, L={L}, Ws={W_scale}) {L+2}x{L+2}...', flush=True)
    try:
        R = M.BKZ(block_size=block_size)
    except Exception as e:
        print(f'  BKZ failed: {e}; using LLL', flush=True)
        R = M.LLL()

    best_mx = None
    for r in range(L+2):
        row = R.row(r)
        if row[L] != 0:
            continue
        if abs(row[L+1]) != K:
            continue
        # Recover y: target combo is (y_0,...,y_{L-1},0,-K) for +E constraint
        s = -1 if row[L+1] == K else 1
        y = [s * int(row[i]) for i in range(L)]
        mx = max(abs(yi) for yi in y)
        if best_mx is None or mx < best_mx:
            best_mx = mx
        if all(-center <= yi <= width-1 for yi in y):
            x = [yi + center for yi in y]
            m = bytes(0x61 + xi for xi in x)
            M_m = int.from_bytes(b'SECUREHASH_' + m, 'big')
            if M_m % N == M_TARGET % N and m != TARGET:
                return m
    print(f'    best max|y|={best_mx}', flush=True)
    return None

for params in [(60,20), (70,20), (80,20), (80,30), (80,40), (100,30), (120,30)]:
    L, bs = params
    print(f'[+] L={L} bs={bs}', flush=True)
    m = find_collision(L, block_size=bs)
    if m is not None:
        print(f'[!] L={L} m = {m}', flush=True)
        print(f'RESULT: {m.decode()}')
        raise SystemExit(0)

print('NO COLLISION FOUND', flush=True)
raise SystemExit(1)
