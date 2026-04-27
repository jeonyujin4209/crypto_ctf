"""
Irish flan (ECSC 2023, Norway) — Quaternion algebra over Z/n with conjugation

Vulnerability:
  Public key:  n, alpha, beta = chi^-1 * alpha^-1 * chi, gamma = chi^r
  Per-message: eps = delta^-1 * alpha * delta, kappa = delta^-1 * beta * delta,
               mu  = kappa * k * kappa,   K = SHA256(str(k)),  c = AES_CBC(K, msg)
               where delta = gamma^s, both r and s random.

  To decrypt we need k, hence kappa, hence chi (since kappa = chi^-1 * eps^-1 * chi).

  The trick: we have TWO linear constraints on chi over the quaternion algebra.
    (1)  alpha * chi - chi * beta^-1 = 0           (since alpha*chi = chi*beta^-1)
    (2)  gamma * chi - chi * gamma   = 0           (since chi commutes with gamma=chi^r)
  Each gives 4 linear equations in the 4 components of chi over Z/n.
  Combined 8x4 system has rank 3 generically, so kernel is 1-dim — recovers chi up
  to a scalar multiple (which is irrelevant: conjugation by c*chi == conjugation by chi).

  The kernel can be computed by 3x3 cofactors (no modular inverses needed against n),
  so it works even for composite n = pq.

Attack:
  1. Build 4x4 matrices L_alpha, R_{beta^-1}, L_gamma, R_gamma (left/right multiplication)
  2. Stack two 4x4 difference matrices into 8x4 matrix A.
  3. Find 3 linearly independent rows such that the 3x4 matrix has 1-dim null space; take
     null vector from cofactors.
  4. Reconstruct chi (up to scalar).
  5. kappa = chi^-1 * eps^-1 * chi
  6. k = kappa^-1 * mu * kappa^-1
  7. K = SHA256(str(k)) → AES decrypt.
"""

import re
import hashlib
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ----- Z/n element class (mirrors challenge) -----
def Z(M):
    class R:
        def __init__(self, r):
            self.r = r % M
        def __add__(self, o): return R(self.r + o.r)
        def __sub__(self, o): return R(self.r - o.r)
        def __neg__(self): return R(-self.r)
        def __mul__(self, o):
            if isinstance(o, int): return R(self.r * o)
            return R(self.r * o.r)
        def __pow__(self, o): return R(pow(self.r, o, M))
        def __truediv__(self, o): return self * o**-1
        def __repr__(self): return f"{self.r} (mod {M})"
        def __str__(self): return f"{self.r} (mod {M})"
    return R

class Q:
    def __init__(self, a, b, c, d):
        self.a, self.b, self.c, self.d = a, b, c, d
    def __add__(s, o): return Q(s.a+o.a, s.b+o.b, s.c+o.c, s.d+o.d)
    def __sub__(s, o): return Q(s.a-o.a, s.b-o.b, s.c-o.c, s.d-o.d)
    def __mul__(s, o):
        if isinstance(o, (int, type(s.a))): return Q(s.a*o, s.b*o, s.c*o, s.d*o)
        return Q(s.a*o.a - s.b*o.b - s.c*o.c - s.d*o.d,
                 s.a*o.b + s.b*o.a + s.c*o.d - s.d*o.c,
                 s.a*o.c - s.b*o.d + s.c*o.a + s.d*o.b,
                 s.a*o.d + s.b*o.c - s.c*o.b + s.d*o.a)
    def __pow__(s, o):
        if o < 0: return s.invert()**(-o)
        res = Q(*map(type(s.a), [1, 0, 0, 0])); c = s
        while o:
            if o & 1: res = res * c
            o >>= 1; c = c * s
        return res
    def invert(s):
        d = s.a**2 + s.b**2 + s.c**2 + s.d**2
        return Q(s.a/d, -s.b/d, -s.c/d, -s.d/d)
    def __str__(s): return "({})".format(",".join(map(str, [s.a, s.b, s.c, s.d])))
    def comps(s): return [s.a.r, s.b.r, s.c.r, s.d.r]

# ----- Parse output.txt -----
with open("output.txt") as f:
    data = f.read()
m = re.search(r"Public key: (.*)\nEncryption: (.*)", data, re.DOTALL)
pub_str, enc_str = m.group(1), m.group(2)
nums_pub = list(map(int, re.findall(r"\d+", pub_str)))
n = nums_pub[0]
ZM = Z(n)
def parse4(idx, src):
    vals = []
    for _ in range(4):
        v = src[idx]; nn = src[idx+1]
        assert nn == n
        vals.append(v); idx += 2
    return vals, idx
idx = 1
alpha_l, idx = parse4(idx, nums_pub)
beta_l,  idx = parse4(idx, nums_pub)
gamma_l, idx = parse4(idx, nums_pub)
m2 = re.match(r'(b".*?"),(.*)', enc_str, re.DOTALL)
ciphertext = eval(m2.group(1))
nums_enc = list(map(int, re.findall(r"\d+", m2.group(2))))
mu_l, j = parse4(0, nums_enc)
eps_l, j = parse4(j, nums_enc)

def to_q(lst):
    return Q(*[ZM(x) for x in lst])
alpha = to_q(alpha_l); beta = to_q(beta_l); gamma = to_q(gamma_l)
mu = to_q(mu_l); eps = to_q(eps_l)
print(f"[+] Parsed n ({n.bit_length()} bits), alpha, beta, gamma, mu, eps")

# Sanity: tr(eps) == tr(alpha)?
print(f"[+] alpha.a == eps.a? {alpha.a.r == eps.a.r}")

# ----- Build linear system on chi -----
# alpha * chi - chi * beta^-1 = 0
# gamma * chi - chi * gamma   = 0
# Each is a 4x4 matrix equation. Stack into 8x4.

def L_mat(p, M):
    pa, pb, pc, pd = [x % M for x in p]
    return [[pa, (-pb)%M, (-pc)%M, (-pd)%M],
            [pb, pa, (-pd)%M, pc],
            [pc, pd, pa, (-pb)%M],
            [pd, (-pc)%M, pb, pa]]
def R_mat(p, M):
    pa, pb, pc, pd = [x % M for x in p]
    return [[pa, (-pb)%M, (-pc)%M, (-pd)%M],
            [pb, pa, pd, (-pc)%M],
            [pc, (-pd)%M, pa, pb],
            [pd, pc, (-pb)%M, pa]]
def msub(A, B):
    return [[(A[i][j]-B[i][j]) % n for j in range(4)] for i in range(4)]

beta_inv_l = (beta**-1).comps()
A1 = msub(L_mat(alpha.comps(), n), R_mat(beta_inv_l, n))
A2 = msub(L_mat(gamma.comps(), n), R_mat(gamma.comps(), n))
A_full = A1 + A2  # 8x4

def det3(M):
    return (M[0][0]*(M[1][1]*M[2][2] - M[1][2]*M[2][1])
          - M[0][1]*(M[1][0]*M[2][2] - M[1][2]*M[2][0])
          + M[0][2]*(M[1][0]*M[2][1] - M[1][1]*M[2][0]))

def kernel_3x4(rows, M):
    v = []
    for j in range(4):
        cols = [c for c in range(4) if c != j]
        minor = [[rows[i][c] for c in cols] for i in range(3)]
        d = det3(minor) % M
        sign = -1 if j % 2 == 1 else 1
        v.append((sign*d) % M)
    return v

# Try triples until we get a non-zero vector that satisfies all 8 rows
chi_rec = None
for triple in itertools.combinations(range(8), 3):
    rows = [A_full[i] for i in triple]
    v = kernel_3x4(rows, n)
    if all(x == 0 for x in v):
        continue
    ok = all(sum(A_full[i][j]*v[j] for j in range(4)) % n == 0 for i in range(8))
    if ok:
        print(f"[+] Found chi (up to scalar) using triple {triple}")
        chi_rec = to_q(v)
        break

assert chi_rec is not None, "Failed to find chi"
print(f"[+] chi_rec = ({chi_rec.a.r}, ..., {chi_rec.d.r})")

# Sanity: alpha*chi_rec should equal chi_rec*beta^-1
lhs = (alpha * chi_rec).comps()
rhs = (chi_rec * (beta**-1)).comps()
assert lhs == rhs, "chi_rec doesn't satisfy alpha*chi = chi*beta^-1"
print("[+] alpha*chi_rec == chi_rec*beta^-1 OK")

# ----- Compute kappa = chi^-1 * eps^-1 * chi (then k = kappa^-1 * mu * kappa^-1) -----
chi_inv = chi_rec.invert()
kappa = chi_inv * eps**-1 * chi_rec
print(f"[+] kappa.a = {kappa.a.r}")
print(f"[+] beta.a  = {beta.a.r}  (should match if conjugation preserves trace)")

k_recovered = kappa**-1 * mu * kappa**-1
print(f"[+] Recovered k:")
print(f"    {k_recovered}")

# ----- Decrypt AES -----
K = hashlib.sha256(str(k_recovered).encode()).digest()
cipher = AES.new(K, AES.MODE_CBC, iv=b"\x00"*16)
plain_padded = cipher.decrypt(ciphertext)
print(f"[+] Plaintext (padded): {plain_padded}")
try:
    plain = unpad(plain_padded, 16)
    print(f"[+] FLAG: {plain.decode()}")
except Exception as e:
    print(f"[-] unpad failed: {e}")
    print(f"    raw: {plain_padded}")
