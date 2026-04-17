"""
Substitution Cipher III (DownUnderCTF 2021)

Matsumoto-Imai (MI) cryptosystem: P = T . (r*x^3) . S over GF(2^80).
Patarin's linearization equation attack (Crypto'95):
  From b = r*a^(q+1), derive a*b^q = r^(q-1)*a^(q^2)*b.
  Since Frobenius x->x^q is linear over GF(2), this gives a BILINEAR relation
  in plaintext x and ciphertext y coordinates:
    sum gamma_ij * x_i * y_j + sum alpha_i * x_i + sum beta_j * y_j + delta = 0
  Valid for ALL (x,y) pairs. Generate (n+1)^2 pairs via public key to recover
  the relation, then substitute known ciphertext and solve the LINEAR system.
"""
import os, time
import numpy as np
from itertools import combinations
from string import printable as PRINTABLE

DIR = os.path.dirname(os.path.abspath(__file__))
n = 80
NCOLS = (n + 1) ** 2  # 6561
NWORDS = (NCOLS + 63) // 64  # 103

# ==================== Parse public key ====================
print("[*] Parsing output.txt...")
with open(os.path.join(DIR, 'output.txt')) as f:
    text = f.read()

lines = text.strip().split('\n')
ct1_str = lines[-2]
ct2_str = lines[-1]

pk = lines[0].strip()
assert pk[0] == '(' and pk[-1] == ')'
poly_strs = pk[1:-1].split(', ')
assert len(poly_strs) == n


def parse_poly(s):
    quads, linears, const = [], [], 0
    for t in s.strip().split(' + '):
        t = t.strip()
        if not t or t == '0':
            continue
        if '*' in t:
            a, b = t.split('*')
            quads.append((int(a[1:]), int(b[1:])))
        elif t == '1':
            const = 1
        elif t.startswith('x'):
            linears.append(int(t[1:]))
    return quads, linears, const


polys = [parse_poly(s) for s in poly_strs]
poly_quad_sets = [set(q) for q, _, _ in polys]
poly_linear_sets = [set(l) for _, l, _ in polys]
poly_consts = [c for _, _, c in polys]
print(f"[+] Parsed {n} polynomials")

# ==================== Encrypt sparse vectors ====================


def encrypt_sparse(nz_bits):
    """Evaluate public key on a sparse binary vector (given nonzero positions)."""
    pairs = [(nz_bits[i], nz_bits[j])
             for i in range(len(nz_bits)) for j in range(i + 1, len(nz_bits))]
    ct = []
    for k in range(n):
        result = poly_consts[k]
        for pair in pairs:
            if pair in poly_quad_sets[k]:
                result ^= 1
        for idx in nz_bits:
            if idx in poly_linear_sets[k]:
                result ^= 1
        ct.append(result)
    return ct


# ==================== Generate pt/ct pairs ====================
def gen_sparse_vectors(N):
    """Generate N unique sparse vectors as sorted lists of nonzero positions."""
    vecs = [[]]  # zero vector
    for i in range(n):
        vecs.append([i])
        if len(vecs) >= N:
            return vecs[:N]
    for c in combinations(range(n), 2):
        vecs.append(list(c))
        if len(vecs) >= N:
            return vecs[:N]
    for c in combinations(range(n), 3):
        vecs.append(list(c))
        if len(vecs) >= N:
            return vecs[:N]
    return vecs[:N]


print(f"[*] Generating {NCOLS} pt/ct pairs...")
t0 = time.time()
sparse_vecs = gen_sparse_vectors(NCOLS)
pairs = [(sv, encrypt_sparse(sv)) for sv in sparse_vecs]
print(f"[+] Encrypted in {time.time()-t0:.1f}s")

# ==================== Build bilinear relation matrix ====================
# Column layout (6561 total):
#   [0..6399]     gamma_{i,j} = x_i * y_j  (col = i*80 + j)
#   [6400..6479]  alpha_i = x_i             (col = 6400 + i)
#   [6480..6559]  beta_j = y_j              (col = 6480 + j)
#   [6560]        delta = 1

print("[*] Building matrix...")
t0 = time.time()

rows_int = []
for sv, ct in pairs:
    y_int = 0
    for j in range(n):
        if ct[j]:
            y_int |= 1 << j
    row = 0
    for i in sv:
        row |= y_int << (i * n)       # x_i * y_j terms
        row |= 1 << (n * n + i)       # x_i term
    row |= y_int << (n * n + n)       # y_j terms
    row |= 1 << (n * n + 2 * n)       # constant
    rows_int.append(row)

print(f"[+] Rows built in {time.time()-t0:.1f}s")

# Convert to numpy uint64 matrix
print("[*] Converting to numpy...")
t0 = time.time()
M = np.zeros((NCOLS, NWORDS), dtype=np.uint64)
mask64 = (1 << 64) - 1
for idx, r in enumerate(rows_int):
    for w in range(NWORDS):
        M[idx, w] = np.uint64(r & mask64)
        r >>= 64
del rows_int
print(f"[+] Converted in {time.time()-t0:.1f}s")

# ==================== RREF over GF(2) using numpy ====================
print("[*] Computing RREF...")
t0 = time.time()
pivots = []
pivot_row = 0

for col in range(NCOLS):
    if pivot_row >= NCOLS:
        break
    w = col // 64
    b = np.uint64(1) << np.uint64(col % 64)

    # Find pivot
    col_slice = M[pivot_row:, w] & b
    nz_idx = np.flatnonzero(col_slice)
    if len(nz_idx) == 0:
        continue
    found = pivot_row + nz_idx[0]

    if found != pivot_row:
        M[[pivot_row, found]] = M[[found, pivot_row]]

    # Eliminate all other rows with this bit set
    elim_mask = (M[:, w] & b).astype(bool)
    elim_mask[pivot_row] = False
    if np.any(elim_mask):
        M[elim_mask] ^= M[pivot_row]

    pivots.append(col)
    pivot_row += 1

    if (col + 1) % 2000 == 0:
        print(f"  col {col+1}/{NCOLS}, rank {len(pivots)}, "
              f"elapsed {time.time()-t0:.1f}s")

nullity = NCOLS - len(pivots)
print(f"[+] RREF done in {time.time()-t0:.1f}s, "
      f"rank={len(pivots)}, nullity={nullity}")

# ==================== Extract right kernel ====================
print("[*] Extracting kernel...")
t0 = time.time()
pivot_set = set(pivots)
free_cols = [j for j in range(NCOLS) if j not in pivot_set]
pivot_to_row = {p: i for i, p in enumerate(pivots)}

kernel = []
for j in free_cols:
    jw = j // 64
    jb = np.uint64(1) << np.uint64(j % 64)
    # Vectorized: check bit j across all pivot rows
    col_bits = M[:len(pivots), jw] & jb
    nz_pivots = np.flatnonzero(col_bits)
    v = 1 << j
    for idx in nz_pivots:
        v |= 1 << pivots[idx]
    kernel.append(v)

print(f"[+] Kernel dim={len(kernel)}, extracted in {time.time()-t0:.1f}s")


# ==================== Recover plaintext ====================
def recover_plaintext(kernel_basis, ct_str):
    """Substitute ciphertext into linearization equations -> linear system in x."""
    Y = [int(c) for c in ct_str]
    y_int = sum(Y[j] << j for j in range(n))
    mask_n = (1 << n) - 1

    # Build linear equations: a_i * x_i = b
    eqs = []
    for kv in kernel_basis:
        coeff = 0
        for i in range(n):
            gamma_i = (kv >> (i * n)) & mask_n
            ai = bin(gamma_i & y_int).count('1') % 2
            ai ^= (kv >> (n * n + i)) & 1
            if ai:
                coeff |= 1 << i
        beta = (kv >> (n * n + n)) & mask_n
        b = bin(beta & y_int).count('1') % 2
        b ^= (kv >> (n * n + 2 * n)) & 1
        eqs.append(coeff | (b << n))

    # Gaussian elimination (augmented 80 x 81)
    piv = []
    for col in range(n):
        found = -1
        for r in range(len(piv), len(eqs)):
            if (eqs[r] >> col) & 1:
                found = r
                break
        if found == -1:
            continue
        idx = len(piv)
        eqs[idx], eqs[found] = eqs[found], eqs[idx]
        for r in range(len(eqs)):
            if r != idx and (eqs[r] >> col) & 1:
                eqs[r] ^= eqs[idx]
        piv.append(col)

    # Particular solution (free vars = 0)
    x0 = 0
    for idx, col in enumerate(piv):
        if (eqs[idx] >> n) & 1:
            x0 |= 1 << col

    # Null space of homogeneous system
    piv_set = set(piv)
    free = [j for j in range(n) if j not in piv_set]
    piv_to_r = {p: i for i, p in enumerate(piv)}
    null_basis = []
    for j in free:
        v = 1 << j
        for p in piv:
            if (eqs[piv_to_r[p]] >> j) & 1:
                v |= 1 << p
        null_basis.append(v)

    print(f"    rank={len(piv)}, free={len(free)}, solutions=2^{len(free)}={1<<len(free)}")

    # Enumerate all solutions
    results = []
    for mask in range(1 << len(null_basis)):
        x = x0
        for k in range(len(null_basis)):
            if (mask >> k) & 1:
                x ^= null_basis[k]
        bits = [(x >> i) & 1 for i in range(n)]
        msg = bytes(int(''.join(str(b) for b in bits[8*j:8*j+8]), 2)
                     for j in range(n // 8))
        msg_stripped = msg.rstrip(b'\x00')
        try:
            decoded = msg_stripped.decode('ascii')
            if all(c in PRINTABLE for c in decoded):
                results.append(decoded)
        except:
            pass
    return results


print("[*] Recovering msg1 from ct1...")
sols1 = recover_plaintext(kernel, ct1_str)
print(f"[+] ct1 printable solutions: {sols1}")

print("[*] Recovering msg2 from ct2...")
sols2 = recover_plaintext(kernel, ct2_str)
print(f"[+] ct2 printable solutions: {sols2}")

for s1 in sols1:
    for s2 in sols2:
        print(f"\n[+] Flag: DUCTF{{{s1}{s2}}}")
