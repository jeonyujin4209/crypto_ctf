import sys
from sage.all import *

# Load output.txt
path = 'C:/Users/UserK/Documents/hackerone/program/crypto_ctf/cryptohack/CTF Archive/2020/1337crypt (DownUnderCTF)/output.txt'
with open(path, 'r') as f:
    content = f.read()

lines = content.strip().split('\n')
hint = Integer(lines[0].split(' = ')[1])
D    = Integer(lines[1].split(' = ')[1])
n    = Integer(lines[2].split(' = ')[1])
c    = eval(lines[3].split(' = ', 1)[1])  # list of integers

print("[*] hint bit length:", hint.nbits())
print("[*] D   =", D)
print("[*] n bit length:", n.nbits())
print("[*] Number of ciphertexts:", len(c))

# ------------------------------------------------------------------
# Step 1: Recover p and q from hint
#
# hint = int(D*sqrt(p) + D*sqrt(q))
# So  s = hint/D  ≈  sqrt(p) + sqrt(q)
# And sqrt(p)*sqrt(q) = sqrt(n)
#
# Let u = sqrt(p), v = sqrt(q).
# u + v = s  (approx)
# u * v = sqrt(n)
#
# So u, v are roots of:  X^2 - s*X + sqrt(n) = 0
#
# We need high precision because p, q are 1337-bit primes.
# sqrt(p) and sqrt(q) are ~669 bits each.
# hint = floor(D*(sqrt(p)+sqrt(q))), so error <= 1
# D ~ 15e24, i.e. ~83 bits.
# So sqrt(p)+sqrt(q) is known to within 1/D ~ 2^{-83}.
# We need ~669 bits of precision, plus safety margin.
# Use ~3000 bits of working precision.
# ------------------------------------------------------------------

PREC = 3000
RF = RealField(PREC)

hint_rf = RF(hint)
D_rf    = RF(D)
n_rf    = RF(n)

s = hint_rf / D_rf          # approx sqrt(p) + sqrt(q)
t = sqrt(n_rf)              # approx sqrt(p) * sqrt(q)

# Discriminant for quadratic X^2 - s*X + t = 0
disc = s*s - 4*t
if disc < 0:
    print("ERROR: discriminant negative - precision issue?")
    sys.exit(1)

sqrtdisc = sqrt(disc)
u = (s + sqrtdisc) / 2      # approx sqrt(p)  (larger root)
v = (s - sqrtdisc) / 2      # approx sqrt(q)  (smaller root)

p_candidate = Integer(u.round()) ** 2
q_candidate = Integer(v.round()) ** 2

# The rounding gives us exact p and q (they are perfect squares of the sqrt roots)
# Verify
if p_candidate * q_candidate == n:
    p = p_candidate
    q = q_candidate
    print("[+] Recovered p and q directly from squared candidates!")
else:
    # Round differently - try nearby integers
    # sqrt(p) rounded should give exact integer square root of p
    # p is prime, so p is NOT a perfect square; we round sqrt(p) then square
    # Actually: hint = int(D*sqrt(p) + D*sqrt(q)) truncates.
    # s = hint/D ≈ sqrt(p)+sqrt(q) with error < 1/D
    # So rounding s to nearest gives sqrt(p)+sqrt(q) very accurately.
    # u_int = round(u) should be isqrt(p) with p = prime, but p is prime not a square.
    # We want p itself. Let's try: p = round(u)^2 adjusted...
    # Actually the approach: round(u)^2 won't give a prime.
    # Let's think again: u ≈ sqrt(p), so p ≈ u^2, meaning p = round(u^2).
    p_candidate2 = Integer(round(RF(u)**2))
    q_candidate2 = n // p_candidate2
    if p_candidate2 * q_candidate2 == n and is_prime(p_candidate2) and is_prime(q_candidate2):
        p = p_candidate2
        q = q_candidate2
        print("[+] Recovered p and q via round(u^2)!")
    else:
        # Try: compute u^2 directly with high precision and round
        u2 = u * u
        v2 = v * v
        for delta_u in range(-2, 3):
            for delta_v in range(-2, 3):
                pp = Integer(u2.round()) + delta_u
                qq = Integer(v2.round()) + delta_v
                if pp * qq == n:
                    p = pp
                    q = qq
                    print(f"[+] Recovered p and q with delta_u={delta_u}, delta_v={delta_v}")
                    break
            else:
                continue
            break
        else:
            # Last resort: factor n using p_candidate
            from sage.arith.misc import gcd as sgcd
            u_int = Integer(u.round())
            for delta in range(-5, 6):
                g = sgcd(Integer(u_int + delta)**2 - n, n)  # won't work as gcd of difference
                # Try p = u_int + delta as a divisor candidate
                candidate = u_int + delta
                if n % candidate == 0:
                    p = candidate
                    q = n // candidate
                    if is_prime(p) and is_prime(q):
                        print(f"[+] Recovered p and q with linear delta={delta}")
                        break
            else:
                print("[-] Could not recover p and q!")
                sys.exit(1)

print("[+] p (first 40 digits):", str(p)[:40], "...")
print("[+] q (first 40 digits):", str(q)[:40], "...")
print("[+] p*q == n:", p*q == n)
print("[+] is_prime(p):", is_prime(p))
print("[+] is_prime(q):", is_prime(q))

# ------------------------------------------------------------------
# Step 2: Decrypt Goldwasser-Micali ciphertext
#
# c_i = pow(x, 1337+b, n) * pow(r, 2674, n)  mod n
# Legendre(r^2674, p) = Legendre(r, p)^2674 = 1  (even exponent)
# Legendre(x, p) = -1
# Legendre(c_i, p) = (-1)^(1337+b) * 1 = (-1)^(1337+b)
#
# 1337 is odd:
#   b=0 => exponent 1337 (odd)  => Legendre = -1
#   b=1 => exponent 1338 (even) => Legendre = +1
#
# So: bit b = 1 iff Legendre(c_i, p) == 1
#         b = 0 iff Legendre(c_i, p) == -1
# ------------------------------------------------------------------

bits = []
for ci in c:
    leg = legendre_symbol(ci, p)
    bits.append(1 if leg == 1 else 0)

print("[*] Number of bits recovered:", len(bits))

# Convert bits to integer
bit_str = ''.join(map(str, bits))
m_int = Integer(int(bit_str, 2))

# Convert integer to bytes
flag_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')

try:
    flag = flag_bytes.decode('utf-8')
    print("[+] Flag:", flag)
except Exception as e:
    print("[-] Could not decode as UTF-8:", e)
    print("[*] Raw bytes:", flag_bytes)
    print("[*] Trying latin-1:", flag_bytes.decode('latin-1'))
