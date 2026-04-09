import numpy as np
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from math import gcd, isqrt
from sympy import factorint
import time

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

I = np.eye(n, dtype=np.uint8)

order = 1427247692705959880439315947500961989719490561
p1 = 2305843009213693951  # 61 bits (Mersenne prime 2^61 - 1)
p2 = 618970019642690137449562111  # 89 bits

# Pohlig-Hellman: solve G^A_priv = A_pub
# Solve DLP mod p1 and mod p2 separately, then CRT

# For p1 (61 bits): BSGS with m = ceil(sqrt(p1)) ~ 2^30.5
# This needs ~1.5G matrix entries in the hash table - too much memory.
# But we can use matrix hashing to reduce memory.

# Actually, let me try a smarter approach.
# For BSGS on matrices over GF(2), each matrix is 150x150 = 22500 bits = ~2.8KB
# 2^31 entries * 2.8KB = 6TB - way too much.

# Alternative: Use Pollard's rho for discrete log on matrices.
# It requires only O(1) memory and O(sqrt(order)) time.

# For p1 = 2^61 - 1, sqrt ~ 2^30.5, each step is a matrix multiply.
# Matrix multiply 150x150 over GF(2) is fast.

# Pollard's rho for DLP: find A_priv mod p1
# Work in the quotient group of order p1

print(f'Solving DLP mod p1 = {p1} using Pollard rho...')

exp1 = order // p1
G1 = mat_pow_gf2(G, exp1)
H1 = mat_pow_gf2(A_pub, exp1)

# G1 has order p1, H1 = G1^A_priv_mod_p1

def mat_hash(M):
    return M.tobytes()

def pollard_rho_dlog(g, h, order, mat_mul, mat_pow, identity):
    """Pollard rho for discrete log: find x such that g^x = h, where g has given order."""
    # Partition function based on hash of matrix
    def partition(X):
        return X[0][0] % 3  # use (0,0) element as partition

    def step(X, a, b):
        s = partition(X)
        if s == 0:
            return mat_mul(X, X), (2*a) % order, (2*b) % order
        elif s == 1:
            return mat_mul(X, g), (a+1) % order, b
        else:
            return mat_mul(X, h), a, (b+1) % order

    # Initialize
    X = identity.copy()
    a, b = 0, 0
    Y = identity.copy()
    A, B = 0, 0

    for i in range(1, 4 * isqrt(order) + 10):
        X, a, b = step(X, a, b)
        Y, A, B = step(Y, A, B)
        Y, A, B = step(Y, A, B)

        if np.array_equal(X, Y):
            # a*log + b = A*log + B (mod order)
            # (a - A)*log = (B - b) (mod order)
            r = (a - A) % order
            s = (B - b) % order
            if r == 0:
                if s == 0:
                    print(f'  Trivial collision at step {i}, retrying...')
                    continue
                else:
                    print(f'  No solution (r=0, s!=0) at step {i}')
                    return None
            g_r = gcd(r, order)
            if s % g_r != 0:
                print(f'  gcd issue at step {i}')
                return None
            # Solve r*x = s (mod order)
            r_inv = pow(r // g_r, -1, order // g_r)
            x0 = (r_inv * (s // g_r)) % (order // g_r)
            # Check all possible solutions
            for k in range(g_r):
                x = x0 + k * (order // g_r)
                if np.array_equal(mat_pow(g, x), h):
                    return x
            print(f'  None of the {g_r} solutions worked at step {i}')
            return None

        if i % 1000000 == 0:
            print(f'  Step {i}...')

    return None

t0 = time.time()
x1 = pollard_rho_dlog(G1, H1, p1, mat_mul_gf2, mat_pow_gf2, I)
print(f'A_priv mod p1 = {x1} (took {time.time()-t0:.1f}s)')

print(f'Solving DLP mod p2 = {p2} using Pollard rho...')
exp2 = order // p2
G2 = mat_pow_gf2(G, exp2)
H2 = mat_pow_gf2(A_pub, exp2)

t0 = time.time()
x2 = pollard_rho_dlog(G2, H2, p2, mat_mul_gf2, mat_pow_gf2, I)
print(f'A_priv mod p2 = {x2} (took {time.time()-t0:.1f}s)')

if x1 is not None and x2 is not None:
    # CRT: A_priv = x1 mod p1, A_priv = x2 mod p2
    from sympy.ntheory.modular import crt
    A_priv_mod, _ = crt([p1, p2], [x1, x2])
    print(f'A_priv mod order = {A_priv_mod}')

    # Verify
    test = mat_pow_gf2(G, A_priv_mod)
    if np.array_equal(test, A_pub):
        print('Verified!')
    else:
        print('Verification failed, trying other CRT solutions...')
        # A_priv might not equal A_priv_mod since A_priv is a 149-bit prime
        # But A_priv mod order = A_priv_mod (since A_priv < P and order ~ 150 bits)
        # Actually order is 150 bits and A_priv is 149 bits, so A_priv < order.
        # So A_priv = A_priv_mod should work.

    # Compute shared secret
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
        # Try 16-byte key
        key16 = sha256(mat_str.encode()).digest()[:16]
        cipher2 = AES.new(key16, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher2.decrypt(ct), 16)
            print(f'Flag (16-byte key): {pt}')
        except Exception as ex2:
            print(f'Also failed: {ex2}')
