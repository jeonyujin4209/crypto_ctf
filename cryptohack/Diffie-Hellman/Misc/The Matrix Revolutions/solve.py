import numpy as np
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from math import gcd

n = 150

def read_gf2_matrix(fname):
    lines = open(fname).read().strip().split('\n')
    return np.array([[int(c) for c in line] for line in lines], dtype=np.uint8)

G = read_gf2_matrix('generator.txt')
A_pub = read_gf2_matrix('alice.pub')
B_pub = read_gf2_matrix('bob.pub')

with open('flag.enc') as f:
    flag_data = json.load(f)

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

# Compute minimal polynomial via Berlekamp-Massey on random vector
np.random.seed(42)
v = np.random.randint(0, 2, size=n).astype(np.uint8)

print('Computing matrix-vector sequence...')
seq = []
cur = v.copy()
for i in range(2 * n + 1):
    seq.append(int(cur[0]))
    cur = np.mod(G.astype(np.int64) @ cur.astype(np.int64), 2).astype(np.uint8)

def berlekamp_massey_gf2(s):
    nn = len(s)
    C = [1]
    B = [1]
    L = 0
    m = 1
    for i in range(nn):
        d = s[i]
        for j in range(1, len(C)):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            shift = [0] * m + B
            while len(shift) < len(C):
                shift.append(0)
            while len(C) < len(shift):
                C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            L = i + 1 - L
            B = T
            m = 1
        else:
            shift = [0] * m + B
            while len(shift) < len(C):
                shift.append(0)
            while len(C) < len(shift):
                C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            m += 1
    return L, C

L, min_poly_list = berlekamp_massey_gf2(seq)
print(f'Minimal polynomial degree: {L}')

# GF(2) polynomial ops using integers
def poly_to_int(coeffs):
    val = 0
    for i, c in enumerate(coeffs):
        if c:
            val |= (1 << i)
    return val

def gf2_deg(p):
    if p == 0:
        return -1
    return p.bit_length() - 1

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

def gf2_powmod(base, exp, mod):
    result = 1
    base = gf2_mod(base, mod)
    while exp > 0:
        if exp & 1:
            result = gf2_mod(gf2_mul(result, base), mod)
        base = gf2_mod(gf2_mul(base, base), mod)
        exp >>= 1
    return result

def gf2_gcd(a, b):
    while b:
        a, b = b, gf2_mod(a, b)
    return a

mp = poly_to_int(min_poly_list)
print(f'Min poly degree: {gf2_deg(mp)}')

# Factor minimal polynomial over GF(2)
print('Factoring minimal polynomial over GF(2)...')
remaining = mp
factor_degrees = []
x = 2  # polynomial x

xpow_d = x  # will hold x^(2^d) mod remaining
for d in range(1, gf2_deg(remaining) + 1):
    if gf2_deg(remaining) < 2 * d:
        if gf2_deg(remaining) > 0:
            factor_degrees.append(gf2_deg(remaining))
            print(f'  Remaining irreducible of degree {gf2_deg(remaining)}')
        break

    # x^(2^d) = (x^(2^(d-1)))^2 mod remaining
    xpow_d = gf2_powmod(xpow_d, 2, remaining)

    # gcd(remaining, x^(2^d) + x)
    xpd_plus_x = xpow_d ^ x
    g = gf2_gcd(remaining, xpd_plus_x)

    if gf2_deg(g) > 0:
        num = gf2_deg(g) // d
        print(f'  Degree {d}: {num} factor(s)')
        factor_degrees.extend([d] * num)
        # Divide out g
        q, r = gf2_divmod(remaining, g)
        assert r == 0, f'Division error at degree {d}'
        remaining = q
        # Recompute xpow_d mod new remaining
        xpow_d = gf2_mod(xpow_d, remaining) if remaining > 1 else 0

print(f'Factor degrees: {factor_degrees}')
print(f'Sum: {sum(factor_degrees)}, expected: {L}')

# Compute order upper bound: lcm(2^d - 1 for d in factor_degrees)
def lcm(a, b):
    return a * b // gcd(a, b)

order_bound = 1
for d in factor_degrees:
    order_bound = lcm(order_bound, (1 << d) - 1)

print(f'Order divides value of {order_bound.bit_length()} bits')

# Factor the order bound
from sympy import factorint
print('Factoring order bound...')
factors = factorint(order_bound)
print(f'Prime factorization: {factors}')

# Compute actual order of G: for each prime power p^e dividing order_bound,
# check if G^(order_bound/p) = I. If so, reduce.
print('Computing actual order of G...')
I = np.eye(n, dtype=np.uint8)
order = order_bound

for p, e in sorted(factors.items()):
    for _ in range(e):
        test_order = order // p
        test_mat = mat_pow_gf2(G, test_order)
        if np.array_equal(test_mat, I):
            order = test_order
        else:
            break
    print(f'After checking p={p}: order = {order} ({order.bit_length()} bits)')

print(f'Order of G: {order}')
print(f'Order factored: {factorint(order)}')

# Now solve DLP: find A_priv such that G^A_priv = A_pub
# Use Pohlig-Hellman: for each prime power p^e dividing order,
# solve DLP in the subgroup of order p^e

order_factors = factorint(order)
print(f'Solving DLP via Pohlig-Hellman...')

# For each prime factor p of order:
# Compute g_p = G^(order/p^e) (has order p^e)
# Compute a_p = A_pub^(order/p^e)
# Solve: g_p^x = a_p for x in [0, p^e)
# Use baby-step giant-step for each

def mat_eq(A, B):
    return np.array_equal(A, B)

crt_vals = []
crt_mods = []

for p, e in order_factors.items():
    pe = p ** e
    exp = order // pe
    g_p = mat_pow_gf2(G, exp)
    a_p = mat_pow_gf2(A_pub, exp)

    # Solve g_p^x = a_p, x in [0, pe)
    # For small pe, brute force. For larger, BSGS.
    if pe <= 10**6:
        # BSGS
        from math import isqrt
        m = isqrt(pe) + 1
        # Baby steps: g_p^j for j = 0..m-1
        table = {}
        cur = np.eye(n, dtype=np.uint8)
        for j in range(m):
            key = cur.tobytes()
            table[key] = j
            cur = mat_mul_gf2(cur, g_p)

        # Giant steps: a_p * (g_p^(-m))^i
        # g_p^(-m) = g_p^(pe - m) since g_p has order pe
        g_p_neg_m = mat_pow_gf2(g_p, pe - m)
        cur = a_p.copy()
        found = False
        for i in range(m):
            key = cur.tobytes()
            if key in table:
                x = (i * m + table[key]) % pe
                print(f'  p={p}, e={e}: x = {x}')
                crt_vals.append(x)
                crt_mods.append(pe)
                found = True
                break
            cur = mat_mul_gf2(cur, g_p_neg_m)
        if not found:
            print(f'  p={p}, e={e}: BSGS failed!')
    else:
        print(f'  p={p}, e={e}: pe={pe} too large for BSGS')

# CRT to combine
from sympy.ntheory.modular import crt as sympy_crt
if crt_vals:
    result = sympy_crt(crt_mods, crt_vals)
    if result:
        A_priv = result[0]
        print(f'A_priv = {A_priv}')

        # Verify
        test = mat_pow_gf2(G, A_priv)
        if mat_eq(test, A_pub):
            print('Verified: G^A_priv = A_pub')
        else:
            print('Verification failed!')

        # Compute shared secret
        shared = mat_pow_gf2(B_pub, A_priv)

        # Derive key
        mat_str = ''.join(str(x) for row in shared for x in row)
        key = sha256(mat_str.encode()).digest()[:32]  # KEY_LENGTH=128 but SHA256 is 32 bytes

        iv = bytes.fromhex(flag_data['iv'])
        ct = bytes.fromhex(flag_data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher.decrypt(ct), 16)
            print(f'Flag: {pt}')
        except Exception as ex:
            print(f'Decryption error: {ex}')
            # Try KEY_LENGTH=128 bits = 16 bytes
            key16 = sha256(mat_str.encode()).digest()[:16]
            cipher2 = AES.new(key16, AES.MODE_CBC, iv)
            try:
                pt = unpad(cipher2.decrypt(ct), 16)
                print(f'Flag (16-byte key): {pt}')
            except Exception as ex2:
                print(f'Also failed with 16 bytes: {ex2}')
