import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

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

# Compute Krylov basis: v, Gv, G^2v, ..., G^29v
krylov = [v_vec]
cur = v_vec
for i in range(29):
    cur = mat_vec(G, cur, P)
    krylov.append(cur)

# Solve: w = c_0*krylov[0] + ... + c_29*krylov[29]
def solve_system(krylov, target, n, P):
    aug = []
    for i in range(n):
        row = [krylov[j][i] for j in range(n)] + [target[i]]
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
print(f'Coefficients found: c[0]={c[0]}, c[1]={c[1]}')

# Compute minimal polynomial via G^30*v
g30v = mat_vec(G, krylov[29], P)
d = solve_system(krylov, g30v, N, P)
min_poly = [(-d[i]) % P for i in range(N)] + [1]
print(f'Minimal polynomial computed (degree {len(min_poly)-1})')

# Polynomial arithmetic in GF(P)[x]
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
    if b == [0] or not b:
        raise ZeroDivisionError
    a = list(a)
    db = len(b) - 1
    inv_lead = pow(b[-1], p-2, p)
    q = []
    while len(a) - 1 >= db and len(a) > 0:
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
    while b != [0] and len(b) > 0:
        _, r = poly_divmod(a, b, p)
        a = b
        b = r if r else [0]
    if len(a) > 0 and a[-1] != 0:
        inv = pow(a[-1], p-2, p)
        a = [(cc * inv) % p for cc in a]
    return a

# Compute x^P mod min_poly
print('Computing x^P mod min_poly...')
x = [0, 1]
xP = poly_powmod(x, P, min_poly, P)
print(f'x^P mod min_poly has degree {len(xP)-1}')

# x^P - x mod min_poly
xP_minus_x = list(xP)
while len(xP_minus_x) < 2:
    xP_minus_x.append(0)
xP_minus_x[1] = (xP_minus_x[1] - 1) % P
# Remove trailing zeros
while xP_minus_x and xP_minus_x[-1] == 0:
    xP_minus_x.pop()
if not xP_minus_x:
    xP_minus_x = [0]

g = poly_gcd(list(min_poly), xP_minus_x, P)
num_roots = len(g) - 1
print(f'Number of roots in GF(P): {num_roots}')

if num_roots == 0:
    print('No roots in GF(P). Checking if min_poly factors into irreducibles...')
    # Check degree-2 factors: gcd(min_poly, x^(P^2) - x)
    print('Computing x^(P^2) mod min_poly...')
    xP2 = poly_powmod(xP, P, min_poly, P)
    xP2_minus_x = list(xP2)
    while len(xP2_minus_x) < 2:
        xP2_minus_x.append(0)
    xP2_minus_x[1] = (xP2_minus_x[1] - 1) % P
    while xP2_minus_x and xP2_minus_x[-1] == 0:
        xP2_minus_x.pop()
    if not xP2_minus_x:
        xP2_minus_x = [0]

    g2 = poly_gcd(list(min_poly), xP2_minus_x, P)
    print(f'Factors of degree <= 2: degree {len(g2)-1}')

    # Degree 3
    print('Computing x^(P^3) mod min_poly...')
    xP3 = poly_powmod(xP2, P, min_poly, P)
    xP3_minus_x = list(xP3)
    while len(xP3_minus_x) < 2:
        xP3_minus_x.append(0)
    xP3_minus_x[1] = (xP3_minus_x[1] - 1) % P
    while xP3_minus_x and xP3_minus_x[-1] == 0:
        xP3_minus_x.pop()
    if not xP3_minus_x:
        xP3_minus_x = [0]

    g3 = poly_gcd(list(min_poly), xP3_minus_x, P)
    print(f'Factors of degree <= 3: degree {len(g3)-1}')

    # Continue checking
    xPk = xP3
    for k in range(4, 31):
        xPk = poly_powmod(xPk, P, min_poly, P)
        xPk_minus_x = list(xPk)
        while len(xPk_minus_x) < 2:
            xPk_minus_x.append(0)
        xPk_minus_x[1] = (xPk_minus_x[1] - 1) % P
        while xPk_minus_x and xPk_minus_x[-1] == 0:
            xPk_minus_x.pop()
        if not xPk_minus_x:
            xPk_minus_x = [0]
        gk = poly_gcd(list(min_poly), xPk_minus_x, P)
        print(f'Factors of degree <= {k}: degree {len(gk)-1}')
        if len(gk) - 1 == 30:
            break

elif num_roots >= 1:
    # Find individual roots
    import random
    random.seed(42)

    def find_roots(f, p):
        """Find roots of polynomial f in GF(p)"""
        deg = len(f) - 1
        if deg == 1:
            return [(-f[0] * pow(f[1], p-2, p)) % p]
        if deg == 0:
            return []

        roots = []
        # Split using random elements
        while len(roots) < deg:
            r = random.randint(0, p-1)
            # Compute gcd(f, (x-r)^((p-1)/2) - 1)
            shifted = [(-r) % p, 1]  # x - r
            half = poly_powmod(shifted, (p-1)//2, f, p)
            half[0] = (half[0] - 1) % p
            while half and half[-1] == 0:
                half.pop()
            if not half:
                half = [0]

            g1 = poly_gcd(list(f), half, p)
            if 1 <= len(g1) - 1 < deg:
                _, f2 = poly_divmod(f, g1, p)
                # Make f2 monic
                if f2[-1] != 1:
                    inv = pow(f2[-1], p-2, p)
                    f2 = [(cc * inv) % p for cc in f2]
                roots.extend(find_roots(g1, p))
                roots.extend(find_roots(f2, p))
                return roots
        return roots

    print(f'Finding {num_roots} roots...')
    roots = find_roots(g, P)
    print(f'Found roots: {len(roots)}')

    if roots:
        lam = roots[0]
        print(f'First eigenvalue: {lam}')

        # Compute target = c(lam) = c_0 + c_1*lam + ... + c_29*lam^29 mod P
        target_val = 0
        lam_pow = 1
        for i in range(N):
            target_val = (target_val + c[i] * lam_pow) % P
            lam_pow = (lam_pow * lam) % P

        print(f'target_val = {target_val}')
        print(f'lam^SECRET = target_val mod P')

        # Compute order of lam in GF(P)*
        # P-1 = 2 * 5 * 71 * 100741 * 3008773 * big_prime
        # The order of lam divides P-1

        small_factors = [(2,1), (5,1), (71,1), (100741,1), (3008773,1)]
        big_prime = 61904310039151029991920946929947125988021049100035984966104668122498297705837937582578750931969412337659599315506720713054974065888903238949

        # Check if lam has small order (dividing smooth part)
        smooth_part = 2 * 5 * 71 * 100741 * 3008773
        test = pow(lam, smooth_part, P)
        print(f'lam^smooth_part = {test}')
        if test == 1:
            print('lam has smooth order!')
            # Pohlig-Hellman
            from sympy.ntheory.residues import discrete_log
            SECRET = discrete_log(P, target_val, lam)
            print(f'SECRET = {SECRET}')
        else:
            print('lam order involves big prime factor')
            # Check order
            order = P - 1
            for q, e in small_factors:
                while order % q == 0:
                    if pow(lam, order // q, P) == 1:
                        order //= q
                    else:
                        break
            print(f'Order of lam: {order}')
            print(f'Order bits: {order.bit_length()}')
