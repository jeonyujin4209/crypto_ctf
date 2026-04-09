"""
Matrix Revolutions: solve DLP in extension fields GF(2^61) and GF(2^89).

The characteristic polynomial of G factors as f1(x) * f2(x) over GF(2),
where deg(f1)=61 and deg(f2)=89.

The DLP G^A_priv = A_pub reduces to:
- DLP in GF(2^61)* of order 2^61-1 (Mersenne prime)
- DLP in GF(2^89)* of order 2^89-1

For GF(2^61), field elements are 61-bit integers, field operations are fast.
Pollard rho needs ~2^30.5 field operations, each taking nanoseconds in C
or microseconds in Python. Let's try.
"""
import numpy as np
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from math import gcd, isqrt
from sympy import factorint
import time
import sys

n = 150

def read_gf2_matrix(fname):
    lines = open(fname).read().strip().split('\n')
    return np.array([[int(c) for c in line] for line in lines], dtype=np.uint8)

G = read_gf2_matrix('generator.txt')
A_pub = read_gf2_matrix('alice.pub')
B_pub = read_gf2_matrix('bob.pub')

with open('flag.enc') as f:
    flag_data = json.load(f)

# Step 1: Find the characteristic polynomial of G
# Use Berlekamp-Massey on a random vector sequence
np.random.seed(42)
v = np.random.randint(0, 2, size=n).astype(np.uint8)

seq = []
cur = v.copy()
for i in range(2 * n + 1):
    seq.append(int(cur[0]))
    cur = np.mod(G.astype(np.int64) @ cur.astype(np.int64), 2).astype(np.uint8)

def berlekamp_massey_gf2(s):
    nn = len(s)
    C, B = [1], [1]
    L, m = 0, 1
    for i in range(nn):
        d = s[i]
        for j in range(1, len(C)):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            shift = [0] * m + B
            while len(shift) < len(C): shift.append(0)
            while len(C) < len(shift): C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            L, B, m = i + 1 - L, T, 1
        else:
            shift = [0] * m + B
            while len(shift) < len(C): shift.append(0)
            while len(C) < len(shift): C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            m += 1
    return L, C

L, min_poly_list = berlekamp_massey_gf2(seq)
print(f'Min poly degree: {L}')

# Convert to integer representation
def poly_to_int(coeffs):
    val = 0
    for i, c in enumerate(coeffs):
        if c:
            val |= (1 << i)
    return val

mp = poly_to_int(min_poly_list)

# GF(2) polynomial operations using integers
def gf2_deg(p):
    return p.bit_length() - 1 if p else -1

def gf2_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

def gf2_mod(a, m):
    dm = gf2_deg(m)
    if dm < 0:
        raise ZeroDivisionError
    while gf2_deg(a) >= dm:
        a ^= m << (gf2_deg(a) - dm)
    return a

def gf2_divmod(a, m):
    dm = gf2_deg(m)
    q = 0
    while gf2_deg(a) >= dm:
        shift = gf2_deg(a) - dm
        q ^= (1 << shift)
        a ^= (m << shift)
    return q, a

def gf2_gcd(a, b):
    while b:
        a, b = b, gf2_mod(a, b)
    return a

def gf2_powmod(base, exp, mod):
    result = 1
    base = gf2_mod(base, mod)
    while exp > 0:
        if exp & 1:
            result = gf2_mod(gf2_mul(result, base), mod)
        base = gf2_mod(gf2_mul(base, base), mod)
        exp >>= 1
    return result

# Factor minimal polynomial: find irreducible factors
print('Factoring min poly...')
remaining = mp
x = 2  # polynomial x

factor_polys = []
xpow_d = x
for d in range(1, gf2_deg(remaining) + 1):
    if gf2_deg(remaining) < 2 * d:
        if gf2_deg(remaining) > 0:
            factor_polys.append((remaining, gf2_deg(remaining)))
            print(f'  Irreducible factor of degree {gf2_deg(remaining)}')
        break
    xpow_d = gf2_powmod(xpow_d, 2, remaining)
    xpd_plus_x = xpow_d ^ x
    g = gf2_gcd(remaining, xpd_plus_x)
    if gf2_deg(g) > 0:
        num = gf2_deg(g) // d
        print(f'  Degree {d}: {num} factor(s)')
        # Extract individual factors if there are multiple
        if num == 1:
            factor_polys.append((g, d))
        else:
            # Split g into individual irreducible factors
            # For now assume single factor per degree
            factor_polys.append((g, d))
        q, r = gf2_divmod(remaining, g)
        assert r == 0
        remaining = q
        xpow_d = gf2_mod(xpow_d, remaining) if remaining > 1 else 0

print(f'Factors: {[(hex(f), d) for f, d in factor_polys]}')

# Step 2: Reduce the matrix DLP to extension field DLPs
# For each irreducible factor f_i of degree d_i:
# Work in GF(2)[x] / f_i(x) = GF(2^d_i)
# The matrix G acting on the quotient ring GF(2)[x]/f_i(x) corresponds to
# multiplication by x in that ring.
#
# But we need to reduce A_pub to the same representation.
#
# The approach:
# 1. Pick a random vector v and compute G^k*v for k=0..n-1 (Krylov space)
# 2. In the quotient GF(2)[x]/min_poly(x), x acts as G.
# 3. Express A_pub in terms of G: find polynomial p(x) such that p(G)*v = A_pub*v
# 4. Then solve x^A_priv = p(x) mod min_poly(x)
# 5. This reduces via CRT to x^A_priv = p(x) mod f_i(x) for each factor
# 6. Each is a DLP in GF(2^d_i)*

# Compute the Krylov basis and express A_pub*v in terms of it
krylov_vecs = [v.copy()]
cur = v.copy()
for i in range(n - 1):
    cur = np.mod(G.astype(np.int64) @ cur.astype(np.int64), 2).astype(np.uint8)
    krylov_vecs.append(cur.copy())

# Compute A_pub * v
apub_v = np.mod(A_pub.astype(np.int64) @ v.astype(np.int64), 2).astype(np.uint8)

# Solve: apub_v = c_0*krylov[0] + c_1*krylov[1] + ... + c_{n-1}*krylov[n-1] over GF(2)
# Build matrix K where column j is krylov[j]
K = np.column_stack(krylov_vecs)  # n x n matrix

# Gaussian elimination over GF(2)
target = apub_v.copy()
aug = np.hstack([K, target.reshape(-1, 1)]).copy()

pivot_cols = []
row = 0
for col in range(n):
    found = -1
    for r in range(row, n):
        if aug[r, col]:
            found = r
            break
    if found == -1:
        continue
    aug[[row, found]] = aug[[found, row]].copy()
    for r in range(n):
        if r != row and aug[r, col]:
            aug[r] ^= aug[row]
    pivot_cols.append(col)
    row += 1

# Extract coefficients
c_vec = np.zeros(n, dtype=np.uint8)
for i, col in enumerate(pivot_cols):
    c_vec[col] = aug[i, -1]

# Convert c_vec to polynomial (GF(2))
target_poly = poly_to_int(c_vec)
print(f'A_pub corresponds to polynomial: {hex(target_poly)}')
print(f'Target poly degree: {gf2_deg(target_poly)}')

# Step 3: Solve x^A_priv = target_poly mod f_i(x) for each factor
# In GF(2^d): x is a generator element, target is the target element.
# This is a standard DLP in GF(2^d)*.

# For the 61-degree factor: DLP in GF(2^61)*, order 2^61-1 (Mersenne prime)
# For the 89-degree factor: DLP in GF(2^89)*, order 2^89-1

# Reduce target polynomial mod each factor
results = []
for f_poly, d in factor_polys:
    target_mod = gf2_mod(target_poly, f_poly)
    gen_mod = gf2_mod(2, f_poly)  # x mod f_poly = generator in GF(2^d)

    field_order = (1 << d) - 1
    print(f'\nDLP in GF(2^{d})*, order = {field_order} ({field_order.bit_length()} bits)')
    print(f'  Generator: {hex(gen_mod)}')
    print(f'  Target: {hex(target_mod)}')

    if target_mod == 0:
        print(f'  Target is 0! A_priv has no solution in this component.')
        results.append((0, field_order))
        continue

    if target_mod == 1:
        print(f'  Target is identity. A_priv = 0 mod ord(gen)')
        results.append((0, field_order))
        continue

    # Factor field_order for Pohlig-Hellman
    print(f'  Factoring field order...')
    fo_factors = factorint(field_order)
    print(f'  Factors: {fo_factors}')

    # Check if smooth enough for Pohlig-Hellman
    max_factor = max(fo_factors.keys())
    print(f'  Largest prime factor: {max_factor} ({max_factor.bit_length()} bits)')

    if max_factor.bit_length() <= 40:
        # Pohlig-Hellman is feasible
        print(f'  Using Pohlig-Hellman...')

        # For each prime power p^e dividing field_order:
        dlog_parts = []
        for p, e in fo_factors.items():
            pe = p ** e
            exp = field_order // pe
            g_sub = gf2_powmod(gen_mod, exp, f_poly)
            h_sub = gf2_powmod(target_mod, exp, f_poly)

            # Solve g_sub^x = h_sub in subgroup of order pe
            # For small pe: brute force or BSGS
            if pe <= 10**7:
                m = isqrt(pe) + 1
                # Baby steps
                table = {}
                cur = 1
                for j in range(m):
                    table[cur] = j
                    cur = gf2_mod(gf2_mul(cur, g_sub), f_poly)

                # Giant step factor
                g_neg_m = gf2_powmod(g_sub, pe - m, f_poly)
                cur = h_sub
                found = False
                for i in range(m):
                    if cur in table:
                        x = (i * m + table[cur]) % pe
                        dlog_parts.append((x, pe))
                        print(f'    p={p}^{e}: x = {x}')
                        found = True
                        break
                    cur = gf2_mod(gf2_mul(cur, g_neg_m), f_poly)
                if not found:
                    print(f'    p={p}^{e}: BSGS failed!')
            else:
                # Pollard rho for this subgroup
                print(f'    p={p}^{e}: Using Pollard rho...')

                def prho_step(X, a, b, g, h, f, order):
                    s = X % 3
                    if s == 0:
                        return gf2_mod(gf2_mul(X, X), f), (2*a) % order, (2*b) % order
                    elif s == 1:
                        return gf2_mod(gf2_mul(X, g), f), (a+1) % order, b
                    else:
                        return gf2_mod(gf2_mul(X, h), f), a, (b+1) % order

                X, a_val, b_val = 1, 0, 0
                Y, A_val, B_val = 1, 0, 0
                found = False
                for step in range(1, 4 * isqrt(pe) + 100):
                    X, a_val, b_val = prho_step(X, a_val, b_val, g_sub, h_sub, f_poly, pe)
                    Y, A_val, B_val = prho_step(Y, A_val, B_val, g_sub, h_sub, f_poly, pe)
                    Y, A_val, B_val = prho_step(Y, A_val, B_val, g_sub, h_sub, f_poly, pe)

                    if X == Y:
                        r = (a_val - A_val) % pe
                        s = (B_val - b_val) % pe
                        if r == 0:
                            continue
                        g_r = gcd(r, pe)
                        if s % g_r != 0:
                            continue
                        r_inv = pow(r // g_r, -1, pe // g_r)
                        x0 = (r_inv * (s // g_r)) % (pe // g_r)
                        for k in range(g_r):
                            x = x0 + k * (pe // g_r)
                            if gf2_powmod(g_sub, x, f_poly) == h_sub:
                                dlog_parts.append((x, pe))
                                print(f'    p={p}^{e}: x = {x} (step {step})')
                                found = True
                                break
                        if found:
                            break
                if not found:
                    print(f'    p={p}^{e}: Pollard rho failed')

        # CRT to combine
        if len(dlog_parts) == len(fo_factors):
            from sympy.ntheory.modular import crt
            mods = [m for _, m in dlog_parts]
            vals = [v for v, _ in dlog_parts]
            result_val, _ = crt(mods, vals)
            results.append((result_val, field_order))
            print(f'  DLP solution in GF(2^{d}): {result_val}')

            # Verify
            test = gf2_powmod(gen_mod, result_val, f_poly)
            print(f'  Verified: {test == target_mod}')
    else:
        # Large prime factor - use Pollard rho directly on the full group
        print(f'  Using Pollard rho on full group (may be slow)...')

        def prho_step(X, a, b, g, h, f, order):
            s = X % 3
            if s == 0:
                return gf2_mod(gf2_mul(X, X), f), (2*a) % order, (2*b) % order
            elif s == 1:
                return gf2_mod(gf2_mul(X, g), f), (a+1) % order, b
            else:
                return gf2_mod(gf2_mul(X, h), f), a, (b+1) % order

        X, a_val, b_val = 1, 0, 0
        Y, A_val, B_val = 1, 0, 0
        t0 = time.time()
        for step in range(1, 4 * isqrt(max_factor) + 100):
            X, a_val, b_val = prho_step(X, a_val, b_val, gen_mod, target_mod, f_poly, field_order)
            Y, A_val, B_val = prho_step(Y, A_val, B_val, gen_mod, target_mod, f_poly, field_order)
            Y, A_val, B_val = prho_step(Y, A_val, B_val, gen_mod, target_mod, f_poly, field_order)

            if X == Y:
                r = (a_val - A_val) % field_order
                s = (B_val - b_val) % field_order
                if r == 0:
                    continue
                g_r = gcd(r, field_order)
                if s % g_r != 0:
                    continue
                r_inv = pow(r // g_r, -1, field_order // g_r)
                x0 = (r_inv * (s // g_r)) % (field_order // g_r)
                for k in range(min(g_r, 1000)):
                    x = x0 + k * (field_order // g_r)
                    if gf2_powmod(gen_mod, x, f_poly) == target_mod:
                        results.append((x, field_order))
                        print(f'  DLP solution: {x} (step {step}, {time.time()-t0:.1f}s)')
                        break
                else:
                    continue
                break

            if step % 10000000 == 0:
                print(f'  Step {step}, {time.time()-t0:.1f}s', flush=True)

if len(results) == len(factor_polys):
    # CRT to combine DLP results
    from sympy.ntheory.modular import crt
    mods = [m for _, m in results]
    vals = [v for v, _ in results]
    A_priv_mod, _ = crt(mods, vals)

    # The total order is product of field orders
    total_order = 1
    for _, m in results:
        total_order *= m // gcd(total_order, m)

    print(f'\nA_priv mod {total_order} = {A_priv_mod}')

    # Compute shared secret
    def mat_mul_gf2(A, B):
        return np.mod(A.astype(np.int64) @ B.astype(np.int64), 2).astype(np.uint8)

    def mat_pow_gf2(M, exp):
        result = np.eye(n, dtype=np.uint8)
        base = M.copy()
        while exp > 0:
            if exp & 1:
                result = mat_mul_gf2(result, base)
            base = mat_mul_gf2(base, base)
            exp >>= 1
        return result

    # Verify
    test = mat_pow_gf2(G, A_priv_mod)
    if np.array_equal(test, A_pub):
        print('Verified: G^A_priv = A_pub')
    else:
        print('Verification FAILED')

    shared = mat_pow_gf2(B_pub, A_priv_mod)
    mat_str = ''.join(str(x) for row in shared for x in row)
    key = sha256(mat_str.encode()).digest()[:32]

    iv = bytes.fromhex(flag_data['iv'])
    ct = bytes.fromhex(flag_data['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), 16)
        print(f'Flag: {pt}')
    except Exception as ex:
        print(f'Decryption error: {ex}')
        key16 = sha256(mat_str.encode()).digest()[:16]
        cipher2 = AES.new(key16, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher2.decrypt(ct), 16)
            print(f'Flag (16-byte key): {pt}')
        except:
            print('Also failed with 16-byte key')
