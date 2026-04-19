"""
Gen4 HNP lattice attack in Sage.

Input: gen4_input.json with p, q, H (16 x N hashed values), outs (N outputs).
Output: RESULT: [k_1, ..., k_16] on stdout.

Equation: sum_i k_i * H[i][j] + r_j ≡ outs[j]  (mod p), r_j ∈ [0, q).
Lattice basis ((16+N+1) x (16+N+1)):
  row i (i=0..15): [e_i | W_r * H[i]_{j=0..N-1} | 0]
  row 16+j: [0_16 | p * W_r * e_j | 0]
  row 16+N (target): [0_16 | -W_r * outs[j] | W_K]

Short vector: (k_1, .., k_16, -W_r * r_1, ..., -W_r * r_N, W_K).
"""
import sys, json

data = json.loads(open('gen4_input.json').read())
p = int(data['p']); q = int(data['q'])
H_raw = [[int(v) for v in row] for row in data['H']]
outs = [int(v) for v in data['outs']]
N = len(outs)

# H_raw is 16 rows x N cols, each entry = h_ij
assert len(H_raw) == 16, (len(H_raw), N)

# Weights
W_r = q  # scale r_q-block to about q * q = 2^256 (since r_j < q)
W_K = 2**256

dim = 16 + N + 1
M = Matrix(ZZ, dim, dim)
# k rows
for i in range(16):
    M[i, i] = 1
    for j in range(N):
        M[i, 16 + j] = W_r * H_raw[i][j]
# p slack rows
for j in range(N):
    M[16 + j, 16 + j] = W_r * p
# target row (last)
for j in range(N):
    M[16 + N, 16 + j] = -(W_r * outs[j])
M[16 + N, 16 + N] = W_K

print(f'dim={dim}, starting BKZ', flush=True)
L = M.BKZ(block_size=20)
print('BKZ done, scanning for short vec', flush=True)

def try_extract(row, r_idx=-1):
    """If row has c*W_K in last coord, try to extract k."""
    last = int(row[16 + N])
    if last == 0:
        return None
    if last % W_K != 0:
        if r_idx >= 0:
            print(f'  row {r_idx}: last={last} not multiple of W_K={W_K}, rem={last%W_K}', flush=True)
        return None
    c = last // W_K
    if abs(c) != 1:
        if r_idx >= 0:
            print(f'  row {r_idx}: c={c} (not ±1)', flush=True)
        return None
    sign = c
    k = [sign * int(row[i]) for i in range(16)]
    return k

best = None
for r in range(dim):
    row = L.row(r)
    last_raw = int(row[16 + N])
    if last_raw != 0:
        rat = float(last_raw) / float(W_K)
        print(f'  scan row {r}: last={last_raw} (ratio={rat:.3f})', flush=True)
    k = try_extract(row, r_idx=r)
    if k is None:
        continue
    print(f'row {r}: candidate k[0..3]={[hex(ki)[:20] for ki in k[:4]]}', flush=True)
    # Verify: compute <k, H[:, j]> mod p + mod q, check against outs
    # Try with k as-is; if all k_i ∈ [0, 2^256) and verify, done.
    # Otherwise, k_i might be reduced mod p — try k_i mod p in [0, p) then in [0, 2^256).
    def verify(kv, tag=''):
        mismatch = 0
        for j in range(N):
            s = sum(int(kv[i]) * H_raw[i][j] for i in range(16))
            out = (s % p + s % q) % p
            if out != outs[j]:
                mismatch += 1
        if mismatch > 0:
            print(f'  verify {tag}: mismatch {mismatch}/{N}', flush=True)
        return mismatch == 0
    # Try with k as-is
    if verify(k, tag=f'row {r} asis'):
        best = k
        break
    # Try with each negative k_i shifted by +p (possibly subset of entries).
    # Since shifts of p change mod q, we need the exact shift per k_i.
    # Try shifting ALL negative entries by +p (greedy).
    k_shift = [ki + p if ki < 0 else ki for ki in k]
    if verify(k_shift, tag=f'row {r} shifted'):
        best = k_shift
        break
    # Try shifting ALL entries (positive and negative) by +p if negative, or staying if positive.
    # Also try brute: 2^16 combinations of +0 or +p per k_i
    from itertools import product as iproduct
    found = False
    for flip in iproduct([0, 1], repeat=16):
        kk = [k[i] + flip[i] * p for i in range(16)]
        if verify(kk):
            best = kk
            found = True
            break
    if found:
        break

if best is None:
    # Before giving up, try the key extraction for the whole BKZ basis
    # with mod-p reduction (k_i mod p, then checking if in [0, 2^256))
    for r in range(dim):
        row = L.row(r)
        last_raw = int(row[16 + N])
        if last_raw == 0:
            continue
        if last_raw % W_K != 0:
            continue
        c_t = last_raw // W_K
        if abs(c_t) == 0:
            continue
        # Unscale by c_t
        if c_t not in (1, -1, 2, -2):
            # might still try
            pass
        sign = 1 if c_t > 0 else -1
        k_raw = [sign * int(row[i]) for i in range(16)]
        # Normalize each to [0, p)
        k_mod = [ki % p for ki in k_raw]
        # If mod p gives values > 2^256, might need k - p etc.
        # Also could divide by |c_t|.
        if abs(c_t) != 1:
            inv_c = pow(abs(c_t), -1, p)
            k_mod = [(ki * inv_c) % p for ki in k_mod]
        k_canon = [ki if ki < 2**256 else ki - p for ki in k_mod]
        # Verify with k_canon if all in valid range
        ok_range = all(0 <= ki < 2**256 for ki in k_canon)
        if ok_range:
            def verify_canon(kv):
                for j in range(N):
                    s = sum(int(kv[i]) * H_raw[i][j] for i in range(16))
                    o = (s % p + s % q) % p
                    if o != outs[j]:
                        return False
                return True
            if verify_canon(k_canon):
                best = k_canon
                print(f'  row {r}: canonical k verified, c_t={c_t}', flush=True)
                break
if best is None:
    print('NO RESULT FOUND', flush=True)
    # Print ALL basis rows with norm and last coord
    for r in range(dim):
        row = L.row(r)
        last = int(row[16 + N])
        norm_bits = 0 if row.norm() == 0 else float(log(row.norm(), 2))
        sign_last = '+' if last >= 0 else '-'
        print(f'row {r} last_bits={sign_last}{abs(int(last)).bit_length()} norm_bits={norm_bits:.1f}', flush=True)
    raise SystemExit(1)

best_py = [int(ki) for ki in best]
print('RESULT: ' + json.dumps(best_py), flush=True)
raise SystemExit(0)
