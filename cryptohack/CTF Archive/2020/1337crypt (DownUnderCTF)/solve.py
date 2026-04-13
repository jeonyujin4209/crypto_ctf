"""
1337crypt (DownUnderCTF 2020) solver

Attack outline:
  hint = int(D*sqrt(p) + D*sqrt(q))
  => s = hint/D  ≈  sqrt(p) + sqrt(q)
  => t = sqrt(n)  =  sqrt(p)*sqrt(q)

  sqrt(p) and sqrt(q) are the two roots of:
      X^2 - s*X + t = 0

  Discriminant = s^2 - 4t
  sqrt(p) = (s + sqrt(disc)) / 2
  sqrt(q) = (s - sqrt(disc)) / 2

  Then p = round(sqrt(p))^2  ... wait, p is prime, not a square.
  Actually we want: p ≈ sqrt(p)^2, so p_candidate = round(sqrt(p)^2).
  But since hint = floor(D*sqrt(p) + D*sqrt(q)), the error in s is < 1/D.
  With D ~ 2^83 and sqrt(p) ~ 2^669, we have plenty of precision.

  Better: p = isqrt(p_candidate) rounded, then p = that integer if it divides n.

Decryption:
  c_i = x^(1337+b) * r^(2*1337+2) mod n
  Legendre(c_i, p) = (-1)^(1337+b)   [since r^even has Legendre +1]
  1337 is odd, so:
    b=0 => Legendre = (-1)^1337 = -1
    b=1 => Legendre = (-1)^1338 = +1
  => bit = 1 iff Legendre(c_i, p) == 1
"""

import sys
from mpmath import mp, sqrt as mpsqrt, floor as mpfloor, nint as mpnint
import gmpy2
from Crypto.Util.number import long_to_bytes

# -----------------------------------------------------------------------
# Load output.txt
# -----------------------------------------------------------------------
import os
path = os.path.join(os.path.dirname(__file__), 'output.txt')
with open(path, 'r') as f:
    content = f.read()

lines = content.strip().split('\n')
hint = int(lines[0].split(' = ')[1])
D    = int(lines[1].split(' = ')[1])
n    = int(lines[2].split(' = ')[1])
c    = eval(lines[3].split(' = ', 1)[1])   # list of ints

print(f"[*] hint ({hint.bit_length()} bits)")
print(f"[*] D   = {D}")
print(f"[*] n   ({n.bit_length()} bits)")
print(f"[*] ciphertexts: {len(c)}")

# -----------------------------------------------------------------------
# Step 1: Recover p and q from hint using high-precision arithmetic
# -----------------------------------------------------------------------
# We need enough decimal digits.
# p, q are 1337-bit primes => sqrt(p), sqrt(q) are ~669 bits ~ 202 decimal digits.
# D ~ 15e24 (83 bits ~ 25 decimal digits).
# hint = floor(D*sqrt(p) + D*sqrt(q))
# The floor operation introduces error < 1, so s = hint/D approximates sqrt(p)+sqrt(q)
# with error < 1/D ~ 6.4e-26.
# We need to resolve sqrt(p)+sqrt(q) to better than 1 ULP at 669-bit precision.
# Use 1200 decimal digits (= 3984 bits) of working precision for safety.

PREC_DEC = 1500
mp.dps = PREC_DEC

hint_mp = mp.mpf(hint)
D_mp    = mp.mpf(D)
n_mp    = mp.mpf(n)

s = hint_mp / D_mp            # ≈ sqrt(p) + sqrt(q)
t = mpsqrt(n_mp)              # = sqrt(p) * sqrt(q)

disc = s*s - 4*t

if disc < 0:
    print("ERROR: discriminant is negative!")
    sys.exit(1)

sqrtdisc = mpsqrt(disc)

u = (s + sqrtdisc) / 2   # ≈ sqrt(p)  (larger)
v = (s - sqrtdisc) / 2   # ≈ sqrt(q)  (smaller)

# p ≈ u^2, q ≈ v^2 — round to nearest integer
p_approx = int(mpnint(u * u))
q_approx = int(mpnint(v * v))

print(f"[*] p_approx ({p_approx.bit_length()} bits)")
print(f"[*] q_approx ({q_approx.bit_length()} bits)")

# Check if p_approx and q_approx divide n
def try_factor(p_cand, n):
    """Try p_cand and nearby values as a factor of n."""
    for delta in range(-5, 6):
        pp = p_cand + delta
        if pp > 1 and n % pp == 0:
            qq = n // pp
            return pp, qq
    return None, None

p, q = try_factor(p_approx, n)

if p is None:
    # Try using rounded sqrt(p) then squaring
    u_int = int(mpnint(u))
    print(f"[*] Trying via isqrt approach, u_int={u_int}")
    for delta in range(-5, 6):
        pp = (u_int + delta) ** 2
        if n % pp == 0:
            p, q = pp, n // pp
            break
    if p is None:
        # Try: use gmpy2 isqrt on p_approx neighborhood
        isqrt_p = int(gmpy2.isqrt(p_approx))
        for delta in range(-3, 4):
            for sq_delta in range(-3, 4):
                pp = (isqrt_p + delta) ** 2 + sq_delta
                if pp > 1 and n % pp == 0:
                    p, q = pp, n // pp
                    break
            if p is not None:
                break

if p is None:
    print("[-] Could not recover p and q!")
    sys.exit(1)

# Sanity checks
assert p * q == n, "p*q != n!"
assert gmpy2.is_prime(p), "p not prime!"
assert gmpy2.is_prime(q), "q not prime!"

print(f"[+] p recovered! ({p.bit_length()} bits)")
print(f"[+] q recovered! ({q.bit_length()} bits)")
print(f"[+] p*q == n: {p*q == n}")

# -----------------------------------------------------------------------
# Step 2: Decrypt Goldwasser-Micali ciphertexts
#
# c_i = pow(x, 1337+b, n) * pow(r, 2674, n) mod n
# Legendre(r^2674, p) = 1  (even power)
# Legendre(x, p) = -1
# Legendre(c_i, p) = (-1)^(1337+b)
#
# 1337 is odd:
#   b=0: (-1)^1337 = -1  =>  Legendre == -1
#   b=1: (-1)^1338 = +1  =>  Legendre == +1
#
# So: bit = 1 iff Legendre(c_i, p) == +1
# -----------------------------------------------------------------------

def legendre(a, p):
    """Compute Legendre symbol (a/p) using Euler's criterion."""
    ls = pow(a, (p - 1) // 2, p)
    if ls == p - 1:
        return -1
    return ls   # 0 or 1

bits = []
for i, ci in enumerate(c):
    leg = legendre(ci, p)
    bits.append(1 if leg == 1 else 0)

print(f"[*] Recovered {len(bits)} bits")

# Convert bits to bytes
bit_str = ''.join(map(str, bits))
m_int = int(bit_str, 2)
flag_bytes = long_to_bytes(m_int)

print(f"[+] Flag bytes: {flag_bytes}")
try:
    flag = flag_bytes.decode('utf-8')
    print(f"[+] Flag: {flag}")
except Exception as e:
    print(f"[-] UTF-8 decode failed: {e}")
    print(f"[*] Latin-1: {flag_bytes.decode('latin-1')}")
