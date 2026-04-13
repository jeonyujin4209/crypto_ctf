"""
1337crypt (DownUnderCTF 2020) - Correct Solver using Coppersmith

WHY THE PREVIOUS APPROACH FAILED:
  hint = floor(D*sqrt(p) + D*sqrt(q)), where D = (1*3*3*7)^(1+3+3+7) = 63^14 ≈ 2^84
  hint/D ≈ sqrt(p) + sqrt(q)  with error < 1/D ≈ 2^{-84}
  => error in sqrt(p) ≈ 2^{-84}
  => error in p = (sqrt(p))^2 ≈ 2*sqrt(p) * 2^{-84} ≈ 2^669 * 2^{-84} = 2^585

  Old code searched delta in [-5, 5], but the actual error is up to 2^585.
  No matter how much floating-point precision you use, you cannot get p exactly
  this way — the floor() in hint permanently destroys ~85 bits of information.

CORRECT APPROACH (Coppersmith's theorem):
  We know p_approx = round(u^2) where u ≈ sqrt(p).
  Write p = p_approx + delta where |delta| < 2^590.
  Define f(x) = p_approx + x.  We want gcd(f(delta), N) = p.
  Coppersmith finds small roots of f(x) mod N when |x| < N^{1/4} ≈ 2^668.
  Since 2^590 < 2^668, the method works.
"""
import sys
from sage.all import *

proof.all(False)

# ── Load data ─────────────────────────────────────────────────────────────────
import os
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output.txt')
with open(path, 'r') as f:
    content = f.read()

lines = content.strip().split('\n')
hint = Integer(lines[0].split(' = ')[1])
D    = Integer(lines[1].split(' = ')[1])
n    = Integer(lines[2].split(' = ')[1])
c    = eval(lines[3].split(' = ', 1)[1])

print(f"[*] D = {D} ({D.nbits()} bits)")
print(f"[*] n ({n.nbits()} bits)")
print(f"[*] ciphertexts: {len(c)}")

# ── Step 1: High-precision approximation of p ────────────────────────────────
# Use 3000-bit precision so fp arithmetic error is negligible.
# The dominant error comes from the floor() in hint, giving |delta| < 2^590.
PREC = 3000
RF = RealField(PREC)

s = RF(hint) / RF(D)        # ≈ sqrt(p) + sqrt(q)
t = sqrt(RF(n))             # = sqrt(p*q)
disc = s*s - 4*t
sqrtdisc = sqrt(disc)
u = (s + sqrtdisc) / 2      # ≈ sqrt(p)

p_approx = Integer(round(u * u))
print(f"[*] p_approx ({p_approx.nbits()} bits)")

# ── Step 2: Coppersmith small_roots ──────────────────────────────────────────
# f(x) = p_approx + x has root x = p - p_approx (mod p), with |root| < 2^590.
# N^{1/4} ≈ 2^668  >>  2^590, so the bound is comfortably met.
X_bound = ZZ(2)^600

PR.<x> = PolynomialRing(ZZ)
f = p_approx + x

print("[*] Running Coppersmith small_roots ...")
roots = f.change_ring(Integers(n)).small_roots(X=X_bound, beta=0.5, epsilon=0.02)
print(f"[*] Roots found: {roots}")

p = q = None
for r in roots:
    p_cand = p_approx + ZZ(r)
    if n % p_cand == 0:
        p = p_cand
        q = n // p_cand
        print(f"[+] p = {str(p)[:40]}... ({p.nbits()} bits)")
        break

# Also try from q side if needed
if p is None:
    v = (s - sqrtdisc) / 2
    q_approx = Integer(round(v * v))
    fq = q_approx + x
    roots2 = fq.change_ring(Integers(n)).small_roots(X=X_bound, beta=0.5, epsilon=0.02)
    for r in roots2:
        q_cand = q_approx + ZZ(r)
        if n % q_cand == 0:
            q = q_cand
            p = n // q_cand
            break

if p is None:
    print("[-] Coppersmith failed!")
    sys.exit(1)

assert p * q == n
assert is_prime(p) and is_prime(q)
print(f"[+] Factored n successfully!")

# ── Step 3: Decrypt Goldwasser-Micali ────────────────────────────────────────
# c_i = x^(1337+b) * r^(2*1337) mod n
# Legendre(c_i, p) = Legendre(x,p)^(1337+b) = (-1)^(1337+b)   [1337 is odd]
#   b=0 => (-1)^1337 = -1
#   b=1 => (-1)^1338 = +1
# => bit = 1 iff Legendre(c_i, p) == +1

bits = [1 if legendre_symbol(ci, p) == 1 else 0 for ci in c]
bit_str = ''.join(map(str, bits))
m_int = Integer(int(bit_str, 2))
flag_bytes = m_int.to_bytes((m_int.nbits() + 7) // 8, 'big')

print(f"[*] Recovered {len(bits)} bits")
print(f"[+] Flag: {flag_bytes}")
try:
    print(f"[+] Flag (utf8): {flag_bytes.decode()}")
except:
    pass
