import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random
random.seed(12345)

P = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
N = 30

with open('output.txt') as f:
    out = json.load(f)
v_vec = out['v']
w_vec = out['w']

with open('flag.enc') as f:
    flag_data = json.load(f)

lines = open('generator.txt').read().strip().split('\n')
G = [[int(x) for x in line.split(' ')] for line in lines]

def mat_vec(M, v, p):
    n = len(v)
    result = [0]*n
    for i in range(n):
        s = 0
        for j in range(n):
            s = (s + M[i][j] * v[j]) % p
        result[i] = s
    return result

# Build Krylov basis
krylov = [v_vec]
cur = v_vec
for i in range(29):
    cur = mat_vec(G, cur, P)
    krylov.append(cur)

def solve_system(basis, target, n, P):
    aug = []
    for i in range(n):
        row = [basis[j][i] for j in range(n)] + [target[i]]
        aug.append(row)
    for col in range(n):
        pivot = -1
        for row in range(col, n):
            if aug[row][col] % P != 0:
                pivot = row
                break
        if pivot == -1:
            return None
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = pow(aug[col][col], P-2, P)
        for j in range(col, n+1):
            aug[col][j] = (aug[col][j] * inv) % P
        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            for j in range(col, n+1):
                aug[row][j] = (aug[row][j] - factor * aug[col][j]) % P
    return [aug[i][n] for i in range(n)]

c = solve_system(krylov, w_vec, N, P)
g30v = mat_vec(G, krylov[29], P)
d = solve_system(krylov, g30v, N, P)
min_poly = [(-d[i]) % P for i in range(N)] + [1]

# Build the target polynomial: G^SECRET = c[0]*I + c[1]*G + ... + c[29]*G^29
# target_poly(x) = c[0] + c[1]*x + ... + c[29]*x^29
target_poly = c

# Poly operations
def poly_mod(a, m, p):
    a = list(a)
    while len(a) > 0 and a[-1] == 0:
        a.pop()
    dm = len(m) - 1
    inv_lead = pow(m[-1], p-2, p)
    while len(a) > dm:
        coef = (a[-1] * inv_lead) % p
        for i in range(len(m)):
            a[len(a) - len(m) + i] = (a[len(a) - len(m) + i] - coef * m[i]) % p
        while len(a) > 0 and a[-1] == 0:
            a.pop()
    if not a:
        a = [0]
    return a

def poly_mul_mod(a, b, m, p):
    result = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            result[i+j] = (result[i+j] + a[i] * b[j]) % p
    return poly_mod(result, m, p)

def poly_powmod(base, exp, m, p):
    result = [1]
    base = poly_mod(base, m, p)
    while exp > 0:
        if exp % 2 == 1:
            result = poly_mul_mod(result, base, m, p)
        base = poly_mul_mod(base, base, m, p)
        exp //= 2
    return result

def poly_divmod(a, b, p):
    if not b or b == [0]:
        raise ZeroDivisionError
    a = list(a)
    db = len(b) - 1
    inv_lead = pow(b[-1], p-2, p)
    q = []
    while len(a) - 1 >= db:
        coef = (a[-1] * inv_lead) % p
        q.append(coef)
        for i in range(len(b)):
            a[len(a) - len(b) + i] = (a[len(a) - len(b) + i] - coef * b[i]) % p
        a.pop()
    while a and a[-1] == 0:
        a.pop()
    if not a:
        a = [0]
    q.reverse()
    return q, a

def poly_gcd(a, b, p):
    while b and b != [0]:
        _, r = poly_divmod(a, b, p)
        a = b
        b = r
    if a and a[-1] != 0:
        inv = pow(a[-1], p-2, p)
        a = [(cc * inv) % p for cc in a]
    return a

def poly_eval(f, x, p):
    result = 0
    for i in range(len(f)-1, -1, -1):
        result = (result * x + f[i]) % p
    return result

def find_roots(f, p):
    """Find all roots of polynomial f in GF(p)"""
    # Remove trailing zeros
    while f and f[-1] == 0:
        f.pop()
    if not f:
        return []
    deg = len(f) - 1
    if deg == 0:
        return []
    if deg == 1:
        return [(-f[0] * pow(f[1], p-2, p)) % p]

    # Try random splitting
    for _ in range(100):
        r = random.randint(0, p-1)
        # Compute (x+r)^((p-1)/2) mod f - this equals Legendre symbol for each root
        xpr = [r % p, 1]  # x + r
        half = poly_powmod(xpr, (p-1)//2, f, p)
        # gcd(f, half - 1) gives roots where Legendre = 1
        h_minus_1 = list(half)
        h_minus_1[0] = (h_minus_1[0] - 1) % p
        while h_minus_1 and h_minus_1[-1] == 0:
            h_minus_1.pop()
        if not h_minus_1:
            h_minus_1 = [0]

        g1 = poly_gcd(list(f), h_minus_1, p)
        deg1 = len(g1) - 1
        if 1 <= deg1 < deg:
            q, _ = poly_divmod(f, g1, p)
            return find_roots(g1, p) + find_roots(q, p)

    return []

# First, find the linear factor part of min_poly
print('Computing x^P mod min_poly...')
x = [0, 1]
xP = poly_powmod(x, P, min_poly, P)

xP_minus_x = list(xP)
while len(xP_minus_x) < 2:
    xP_minus_x.append(0)
xP_minus_x[1] = (xP_minus_x[1] - 1) % P
while xP_minus_x and xP_minus_x[-1] == 0:
    xP_minus_x.pop()
if not xP_minus_x:
    xP_minus_x = [0]

linear_part = poly_gcd(list(min_poly), xP_minus_x, P)
num_roots = len(linear_part) - 1
print(f'Number of roots in GF(P): {num_roots}')

print('Finding all roots...')
roots = find_roots(linear_part, P)
print(f'Found {len(roots)} roots')

# For each root (eigenvalue), check its order
small_factors = [(2,1), (5,1), (71,1), (100741,1), (3008773,1)]
big_prime = (P-1) // (2 * 5 * 71 * 100741 * 3008773)
smooth_part = 2 * 5 * 71 * 100741 * 3008773

best_root = None
best_order = None

for lam in roots:
    if lam == 0:
        continue
    # Check if lam^smooth_part == 1
    test = pow(lam, smooth_part, P)
    if test == 1:
        # Find exact order (divides smooth_part)
        order = smooth_part
        for q, _ in small_factors:
            while order % q == 0 and pow(lam, order // q, P) == 1:
                order //= q
        print(f'Root {lam}: smooth order = {order}')
        target_val = poly_eval(target_poly, lam, P)
        # Verify target_val^(order) == 1
        if pow(target_val, order, P) != 1:
            print(f'  WARNING: target not in subgroup of this eigenvalue')
            continue
        best_root = lam
        best_order = order
        break
    else:
        # Check the order mod big_prime
        order = P - 1
        for q, _ in small_factors:
            while order % q == 0 and pow(lam, order // q, P) == 1:
                order //= q
        # Don't print all, just note
        pass

if best_root is not None:
    lam = best_root
    target_val = poly_eval(target_poly, lam, P)
    print(f'Solving DLP with smooth order {best_order}')

    # Pohlig-Hellman manually
    from sympy import discrete_log
    SECRET_mod = discrete_log(P, target_val, lam, best_order)
    print(f'SECRET mod {best_order} = {SECRET_mod}')
    # But SECRET can be up to P-1, so this might not give the full SECRET
    # Unless SECRET < smooth_part
    SECRET = SECRET_mod
    KEY = sha256(str(SECRET).encode()).digest()[:32]
    iv = bytes.fromhex(flag_data['iv'])
    ct = bytes.fromhex(flag_data['ciphertext'])
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), 16)
        print(f'Flag: {pt}')
    except:
        print('Decryption failed with this SECRET')
else:
    print('No eigenvalue with smooth order found.')
    print('Trying Pohlig-Hellman on smooth part of all eigenvalues...')

    # Even though the full order is not smooth, we can get SECRET mod smooth_part
    # for each eigenvalue via Pohlig-Hellman, then combine via CRT if needed.
    # But SECRET is a single value, so we get the same SECRET mod smooth_part from any eigenvalue.

    lam = roots[0]
    target_val = poly_eval(target_poly, lam, P)

    # Compute SECRET mod each small prime factor of P-1
    # For prime q dividing P-1: lam^((P-1)/q) has order dividing q
    # target_val^((P-1)/q) = lam^(SECRET*(P-1)/q)
    # This gives SECRET mod q

    from sympy import discrete_log

    crt_mods = []
    crt_vals = []

    for q, e in small_factors:
        g_q = pow(lam, (P-1)//q, P)
        t_q = pow(target_val, (P-1)//q, P)
        if g_q == 1:
            continue
        s_q = discrete_log(P, t_q, g_q, q)
        print(f'SECRET mod {q} = {s_q}')
        crt_mods.append(q)
        crt_vals.append(s_q)

    # This only gives SECRET mod lcm(small primes) which is small.
    # Not enough to recover SECRET.

    # Actually, maybe we should look at this differently.
    # Perhaps the answer is that SECRET is SMALL, or that the problem
    # uses a different approach entirely.

    # Let me check: what if we use multiple eigenvalues?
    # Each gives lam_i^SECRET = target(lam_i)
    # If we have enough equations and the eigenvalues generate a smooth subgroup...
    # No, they're all in the same GF(P)* group.

    # Alternative: maybe the characteristic polynomial of G factors into
    # factors whose degrees give GF(P^d) where P^d - 1 is smooth for small d.

    print('Checking factorization of min_poly...')
    remaining = list(min_poly)
    q_part, _ = poly_divmod(remaining, linear_part, P)
    deg_remaining = len(q_part) - 1
    print(f'After removing linear factors: degree {deg_remaining} remains')

    if deg_remaining > 0:
        # Check if this is irreducible
        # It should be since we found 29 linear factors + 1 factor of degree 1 = 30
        # Wait, 29 linear + degree 1 = 30. So ALL 30 roots are in GF(P)?
        # Actually degree of linear_part is 29, remaining is degree 1.
        print(f'Remaining factor: {q_part}')
        if deg_remaining == 1:
            extra_root = (-q_part[0] * pow(q_part[1], P-2, P)) % P
            print(f'Extra root: {extra_root}')
            roots.append(extra_root)
