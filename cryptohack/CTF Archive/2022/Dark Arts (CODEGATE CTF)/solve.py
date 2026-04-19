"""
Dark Arts (CODEGATE 2022) - breaking (prod%p + prod%q) % p PRFs.

Gen 1 (p=2,q=3, x bits): x=unit-vector → f=0 always in mode 0.
  Query 1,2,4,8,... (hw=1). All zeros ⇒ mode 0; any one ⇒ mode 1.

Gen 2 (p=5,q=7, hashed bits): marginal output ≈ uniform but with Fourier bias.
  Compute Z2 = sum ω^(2f(x)) over N samples. Under mode 0 |Z2/N|^2 ~ 0.009,
  under mode 1 ~ 1/N. Use N=5000 per round, threshold 0.003.

Gen 3 (p=2,q=5, base-5 digits of hash, key∈{0,1,2,3}^64): output = (<k,h> mod 5) mod 2.
  For output=1: <k,h> mod 5 ∈ {1,3} → (y-1)(y-3) ≡ 0 ⇒ y²+y+3 ≡ 0 (mod 5).
  Quadratic in k. Linearize monomials k_i k_j, k_i, const. 2145 variables.
  Need ~2150 output=1 rows → ~5400 queries total. Gauss elim over GF(5).

Gen 4 (256-bit p, 128-bit q, 16×256-bit key, iterated sha256): output mostly = r_p + r_q.
  <k, h_j> ≡ output_j - r_q_j (mod p) with r_q_j ∈ [0, q). HNP lattice:
  dim 16 + N + 1, solve via LLL/BKZ in Sage docker.
"""
import os, sys, time, hashlib, cmath, math, subprocess, json
import numpy as np
from pwn import remote, process, context, log

context.log_level = 'error'

HOST = 'archive.cryptohack.org'
PORT = 35802

def P(*a, **kw):
    print(*a, **kw, flush=True)


# ============= Gen 1: unit-vector distinguisher ============= #

def gen1_distinguish(io, queries=24):
    """Query x=1,2,4,...,2^(queries-1). Mode 0 → all zero. Mode 1 → some nonzero."""
    # Send all queries pipelined
    send_lines = []
    for i in range(queries):
        x = 1 << i
        send_lines.append(b'0')
        send_lines.append(str(x).encode())
    io.send(b'\n'.join(send_lines) + b'\n')
    outs = []
    for _ in range(queries):
        line = io.recvline().strip()
        outs.append(int(line))
    # Guess
    is_mode0 = all(o == 0 for o in outs)
    mode = 0 if is_mode0 else 1
    io.sendline(b'1')
    io.sendline(str(mode).encode())


def gen1_stage(io):
    P('Gen 1: 64 rounds')
    io.recvuntil(b'Challenge 1')
    io.recvline()
    t0 = time.time()
    for r in range(64):
        gen1_distinguish(io, queries=24)
        if r % 16 == 15:
            P(f'  Gen 1 round {r+1}/64 elapsed {time.time()-t0:.1f}s')
    P(f'Gen 1: done in {time.time()-t0:.1f}s')


# ============= Gen 2: Fourier bias distinguisher ============= #

OMEGA = cmath.exp(2j * math.pi / 5)
OMEGA2 = [OMEGA ** (2 * v) for v in range(5)]  # ω^(2v)

def gen2_distinguish(io, queries=5000):
    send_lines = []
    for i in range(queries):
        send_lines.append(b'0')
        send_lines.append(str(i).encode())
    io.send(b'\n'.join(send_lines) + b'\n')
    Z2 = 0 + 0j
    outs = []
    for _ in range(queries):
        line = io.recvline().strip()
        v = int(line)
        Z2 += OMEGA2[v]
        outs.append(v)
    mag_sq = (Z2.real ** 2 + Z2.imag ** 2) / (queries ** 2)
    # Threshold: under mode 1 E[mag_sq] = 1/N ~ 0.0002; under mode 0 ~ 0.009.
    threshold = 0.003
    mode = 0 if mag_sq > threshold else 1
    io.sendline(b'1')
    io.sendline(str(mode).encode())


def gen2_stage(io, queries=5000):
    P(f'Gen 2: 64 rounds ({queries} queries each)')
    io.recvuntil(b'Challenge 2')
    io.recvline()
    t0 = time.time()
    for r in range(64):
        gen2_distinguish(io, queries=queries)
        if r % 8 == 7:
            P(f'  round {r+1}/64, elapsed {time.time()-t0:.1f}s')
    P(f'Gen 2: done in {time.time()-t0:.1f}s')


# ============= Gen 3: quadratic linearization ============= #

N_VARS_3 = 64
QUAD_N = N_VARS_3 * (N_VARS_3 + 1) // 2  # 2080
TOTAL_3 = QUAD_N + N_VARS_3 + 1  # 2145

PAIRS_I = []
PAIRS_J = []
for i in range(N_VARS_3):
    for j in range(i, N_VARS_3):
        PAIRS_I.append(i); PAIRS_J.append(j)
PAIRS_I = np.array(PAIRS_I, dtype=np.int64)
PAIRS_J = np.array(PAIRS_J, dtype=np.int64)
SAME = (PAIRS_I == PAIRS_J)

def hashed_base5(x):
    xi = int.from_bytes(hashlib.sha256(str(x).encode()).digest(), 'big')
    h = np.zeros(N_VARS_3, dtype=np.int64)
    for i in range(N_VARS_3):
        h[i] = xi % 5
        xi //= 5
    return h

def build_rows_gen3(hs):
    M = hs.shape[0]
    rows = np.zeros((M, TOTAL_3), dtype=np.int64)
    quad_block = hs[:, PAIRS_I] * hs[:, PAIRS_J]
    quad_block = np.where(SAME[None, :], quad_block, 2 * quad_block)
    rows[:, :QUAD_N] = quad_block % 5
    rows[:, QUAD_N:QUAD_N + N_VARS_3] = hs % 5
    rows[:, -1] = 3
    return rows

def solve_mod5_vec(A, b):
    p = 5
    INV = np.array([0, 1, 3, 2, 4], dtype=np.int64)
    M_rows, M_cols = A.shape
    M = np.zeros((M_rows, M_cols + 1), dtype=np.int64)
    M[:, :M_cols] = A
    M[:, M_cols] = b
    M %= p
    r = 0
    pivot_cols = []
    for col in range(M_cols):
        nz = np.nonzero(M[r:, col])[0]
        if len(nz) == 0:
            continue
        pr = r + int(nz[0])
        if pr != r:
            tmp = M[r].copy(); M[r] = M[pr]; M[pr] = tmp
        inv = INV[M[r, col]]
        M[r] = (M[r] * inv) % p
        factors = M[:, col].copy()
        factors[r] = 0
        M = (M - factors[:, None] * M[r][None, :]) % p
        pivot_cols.append(col)
        r += 1
        if r == M_rows:
            break
    sol = np.zeros(M_cols, dtype=np.int64)
    for i, col in enumerate(pivot_cols):
        sol[col] = M[i, M_cols]
    return sol

def gen3_stage(io, max_queries=8000):
    P('Gen 3: key recovery')
    io.recvuntil(b'Challenge 3')
    io.recvline()
    # Query max_queries xs = 0..max_queries-1
    t0 = time.time()
    send_lines = []
    for x in range(max_queries):
        send_lines.append(b'0')
        send_lines.append(str(x).encode())
    io.send(b'\n'.join(send_lines) + b'\n')
    outs = []
    for _ in range(max_queries):
        line = io.recvline().strip()
        outs.append(int(line))
    P(f'  sent/recv {max_queries} queries, {time.time()-t0:.1f}s')
    # Build matrix for output=1 rows
    hs_keep = []
    for x, o in enumerate(outs):
        if o == 1:
            hs_keep.append(hashed_base5(x))
            if len(hs_keep) >= TOTAL_3 + 20:
                break
    if len(hs_keep) < TOTAL_3:
        raise RuntimeError(f'Not enough output=1 samples: {len(hs_keep)} < {TOTAL_3}')
    hs_keep = np.array(hs_keep, dtype=np.int64)
    t1 = time.time()
    rows = build_rows_gen3(hs_keep)
    A = rows[:, :-1]
    b = (-rows[:, -1]) % 5
    t2 = time.time()
    P(f'  build rows {t2-t1:.1f}s, starting gauss shape {A.shape}')
    sol = solve_mod5_vec(A, b)
    t3 = time.time()
    P(f'  gauss {t3-t2:.1f}s')
    recovered = sol[QUAD_N:QUAD_N + N_VARS_3].tolist()
    # Submit
    io.sendline(b'1')
    for ki in recovered:
        io.sendline(str(int(ki)).encode())
    P(f'Gen 3: done in {time.time()-t0:.1f}s, submitted key')


# ============= Gen 4: HNP lattice ============= #

def gen4_queries(io, N=30):
    """Read p, q from server, send N queries x=0..N-1, collect outputs."""
    io.recvuntil(b'Challenge 4')
    io.recvline()
    p = int(io.recvline().strip())
    q = int(io.recvline().strip())
    P(f'Gen 4: p={p.bit_length()} bits, q={q.bit_length()} bits')
    send_lines = []
    for x in range(N):
        send_lines.append(b'0')
        send_lines.append(str(x).encode())
    io.send(b'\n'.join(send_lines) + b'\n')
    outs = []
    for _ in range(N):
        outs.append(int(io.recvline().strip()))
    return p, q, outs

def hashed_gen4(x):
    """16 integer values: h_0 = int(sha256(str(x))); h_{i+1} = int(sha256(h_i bytes))."""
    xb = hashlib.sha256(str(x).encode()).digest()
    hs = []
    for _ in range(16):
        hs.append(int.from_bytes(xb, 'big'))
        xb = hashlib.sha256(xb).digest()
    return hs

def gen4_stage(io, N=40):
    p, q, outs = gen4_queries(io, N=N)
    Hcols = [hashed_gen4(x) for x in range(N)]  # N x 16
    # Transpose to 16 x N for lattice (row i = i-th key coord across queries)
    H = [[Hcols[j][i] for j in range(N)] for i in range(16)]
    # Build HNP lattice. Call sage docker.
    HERE = os.path.dirname(os.path.abspath(__file__))
    wd = HERE.replace('\\', '/')
    mount_host = f'/{wd[0].lower()}{wd[2:]}'
    payload = {
        'p': str(p),
        'q': str(q),
        'H': [[str(v) for v in row] for row in H],
        'outs': [str(v) for v in outs],
    }
    with open(os.path.join(HERE, 'gen4_input.json'), 'w') as f:
        json.dump(payload, f)
    env = os.environ.copy()
    env['MSYS_NO_PATHCONV'] = '1'
    cmd = ['docker', 'run', '--rm',
           '-v', f'{mount_host}:/work',
           '-w', '/work',
           'sagemath/sagemath:latest',
           'sage', 'gen4_lattice.sage']
    t0 = time.time()
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=200)
    P(f'Gen 4: sage docker {time.time()-t0:.1f}s, returncode={proc.returncode}')
    key = None
    for line in proc.stdout.splitlines():
        if line.startswith('RESULT: '):
            key = json.loads(line[len('RESULT: '):])
            break
    if key is None:
        P('Gen 4 stderr:', proc.stderr[-800:])
        raise RuntimeError('Gen 4 lattice failed')
    io.sendline(b'1')
    for ki in key:
        io.sendline(str(int(ki)).encode())
    P('Gen 4: done, submitted key')


def main():
    host = HOST if len(sys.argv) < 2 else sys.argv[1]
    port = PORT if len(sys.argv) < 3 else int(sys.argv[2])
    if host == 'local':
        io = process(['python', 'chal_local.py'])
    else:
        io = remote(host, port)
    t0 = time.time()
    try:
        gen1_stage(io)
        gen2_stage(io)
        gen3_stage(io)
        gen4_stage(io)
        # Expect flag
        flag_line = io.recvline_contains(b'{', timeout=30)
        P(f'\nFLAG: {flag_line.decode().strip()}')
    except Exception as e:
        P(f'error: {e}')
        try:
            remaining = io.recvrepeat(1)
            P(f'remaining: {remaining[-500:]}')
        except: pass
    P(f'total {time.time()-t0:.1f}s')

if __name__ == '__main__':
    main()
