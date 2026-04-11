"""
The Matrix Reloaded — final solver

Key insight: the minimal polynomial of G has a *repeated* linear factor
(x - λ)². On the local ring R = GF(P)[x]/(x - λ)², the residue of x^SECRET
admits a closed form:

    x^SECRET ≡ λ^SECRET + SECRET·λ^(SECRET-1)·(x - λ)   (mod (x - λ)²)

(by binomial expansion; only the j=0 and j=1 terms of (λ + (x-λ))^SECRET
survive). Since H = G^SECRET corresponds to the polynomial c(x) (= the
unique polynomial of degree < 30 with H·v = c(G)·v for our generic v),
we have c(x) ≡ x^SECRET mod min_poly. Reducing both sides mod (x - λ)²:

    c(x) ≡ a + b·(x - λ)        with  a = λ^SECRET,  b = SECRET·λ^(SECRET-1)

Therefore  SECRET ≡ λ · b / a   (mod P), recovered DIRECTLY — no DLP needed.
SECRET was sampled in [0, P-1), so reducing mod P is exact.
"""
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
N = 30


def matvec(M, vec):
    n = len(vec)
    return [sum(M[i][j] * vec[j] for j in range(n)) % P for i in range(n)]


def solve_lin(K, target):
    n = len(target)
    aug = [[K[j][i] for j in range(n)] + [target[i]] for i in range(n)]
    for col in range(n):
        pivot = -1
        for row in range(col, n):
            if aug[row][col] != 0:
                pivot = row
                break
        if pivot == -1:
            return None
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = pow(aug[col][col], -1, P)
        for j in range(col, n + 1):
            aug[col][j] = aug[col][j] * inv % P
        for row in range(n):
            if row == col:
                continue
            f = aug[row][col]
            if f == 0:
                continue
            for j in range(col, n + 1):
                aug[row][j] = (aug[row][j] - f * aug[col][j]) % P
    return [aug[i][n] for i in range(n)]


# Load files
with open('output.txt') as f:
    out = json.load(f)
v_vec = out['v']
w_vec = out['w']

with open('flag.enc') as f:
    flag_data = json.load(f)

lines = open('generator.txt').read().strip().split('\n')
G = [[int(x) for x in line.split(' ')] for line in lines]

# Build Krylov basis [v, Gv, ..., G^N v]
print('[1] Building Krylov sequence...')
seq = [v_vec]
cur = v_vec
for _ in range(N + 1):
    cur = matvec(G, cur)
    seq.append(cur)

# Solve K c = w → c is target_poly with c(G)·v = w = H·v
print('[2] Recovering target polynomial c...')
c = solve_lin(seq[:N], w_vec)

# Recover min poly via G^N v = sum d_i G^i v
print('[3] Recovering minimal polynomial...')
d = solve_lin(seq[:N], seq[N])
min_poly = [(-d[i]) % P for i in range(N)] + [1]

# Find the repeated root λ.
# It is a root of gcd(min_poly, min_poly').
def normalize(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    if not a:
        a = [0]
    return a


def poly_divmod(a, b):
    a = list(a)
    b = normalize(list(b))
    if len(b) == 1 and b[0] == 0:
        raise ZeroDivisionError
    db = len(b) - 1
    inv_lead = pow(b[-1], -1, P)
    q = [0] * max(1, len(a) - db)
    while len(a) - 1 >= db and (len(a) > 1 or a[0] != 0):
        coef = a[-1] * inv_lead % P
        idx = len(a) - 1 - db
        q[idx] = coef
        for i in range(len(b)):
            a[idx + i] = (a[idx + i] - coef * b[i]) % P
        a.pop()
    return normalize(q), normalize(a)


def poly_gcd(a, b):
    a = normalize(list(a))
    b = normalize(list(b))
    while not (len(b) == 1 and b[0] == 0):
        _, r = poly_divmod(a, b)
        a, b = b, r
    if a[-1] not in (0, 1):
        inv = pow(a[-1], -1, P)
        a = [(c * inv) % P for c in a]
    return a


# min_poly' (formal derivative)
min_poly_d = [(i * min_poly[i]) % P for i in range(1, len(min_poly))]
g = poly_gcd(min_poly, min_poly_d)
print(f'[4] gcd(min_poly, min_poly_derivative) degree = {len(g)-1}')
assert len(g) == 2, "Expected exactly one repeated linear factor"
# g = (x - λ) up to scaling. Since g is monic, g = [-λ, 1].
lam = (-g[0]) % P
print(f'    repeated root λ = {hex(lam)[:30]}...')

# Reduce c(x) mod (x - λ)^2 = x^2 - 2λx + λ^2
sq = [(lam * lam) % P, (-2 * lam) % P, 1]  # ascending: λ^2 - 2λ x + x^2
_, c_red = poly_divmod(c, sq)
# c_red has degree ≤ 1: c_red = c0 + c1 * x
while len(c_red) < 2:
    c_red.append(0)
c0, c1 = c_red[0], c_red[1]

# Express in (x - λ) basis: c0 + c1*x = (c0 + c1*λ) + c1*(x - λ)
a = (c0 + c1 * lam) % P
b = c1
print(f'[5] c(x) mod (x-λ)^2 = a + b·(x-λ)')
print(f'    a = λ^SECRET = {hex(a)[:30]}...')
print(f'    b = SECRET·λ^(SECRET-1) = {hex(b)[:30]}...')

# SECRET = λ · b / a (mod P)
SECRET = (lam * b % P) * pow(a, -1, P) % P
print(f'[6] SECRET = {SECRET}')

# Verify: λ^SECRET should equal a
assert pow(lam, SECRET, P) == a, "verification failed"
print('    [OK] verified lambda^SECRET == a')

# Decrypt flag
KEY = sha256(str(SECRET).encode()).digest()[:32]
iv = bytes.fromhex(flag_data['iv'])
ct = bytes.fromhex(flag_data['ciphertext'])
pt = unpad(AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct), 16)
print()
print('FLAG:', pt.decode())
