import gmpy2
from mpmath import mp, sqrt as mpsqrt, floor as mpfloor

path = 'C:/Users/UserK/Documents/hackerone/program/crypto_ctf/cryptohack/CTF Archive/2020/1337crypt (DownUnderCTF)/output.txt'
with open(path) as f:
    lines = f.read().strip().split('\n')
hint = int(lines[0].split(' = ')[1])
D    = int(lines[1].split(' = ')[1])
n    = int(lines[2].split(' = ')[1])

mp.prec = 5000
s = mp.mpf(hint) / mp.mpf(D)
t = mpsqrt(mp.mpf(n))
disc = s*s - 4*t
sqrtdisc = mpsqrt(disc)
u = (s + sqrtdisc) / 2
Du = mp.mpf(D) * u
a_approx = int(mpfloor(Du))

a = a_approx + 1
b = hint - a

D4n = D**4 * n
D4n_div_a2 = D4n // a**2
b_from_isqrt = int(gmpy2.isqrt(D4n_div_a2))

print(f'b = (last 30 digits) ...{str(b)[-30:]}')
print(f'b_from_isqrt = (last 30) ...{str(b_from_isqrt)[-30:]}')
print(f'equal: {b == b_from_isqrt}')
print()

r_check = D4n_div_a2 - b**2
print(f'D^4*n // a^2 - b^2 = {r_check}')
print(f'r_check bit length: {r_check.bit_length()}')
print(f'2*b+1 bit length: {(2*b+1).bit_length()}')
print(f'r_check < 2*b+1: {r_check < 2*b+1}')
print()

# Great! So D^4*n // a^2 = b^2 + r_check where r_check < 2b+1 = 2*isqrt(D^2*q)+1.
# This means r_check in [0, 2b] = [0, 2*isqrt(D^2*q)].
# And D^4*n // a^2 = D^2*q + floor(D^2*q*k/a^2) where k = D^2*p - a^2.
# So b^2 + r_check = D^2*q + floor(D^2*q*k/a^2) where b^2 <= D^2*q < (b+1)^2.
# r_check = (D^2*q - b^2) + floor(D^2*q*k/a^2).
# Both terms are non-negative, and r_check < 2b+1.
# So: floor(D^2*q*k/a^2) <= 2b - (D^2*q - b^2) <= 2b (small).
# And: D^2*q * k / a^2 <= 2b + 1. So k < (2b+1) * a^2 / D^2*q ~ 2b * a^2 / (b^2) ~ 2a^2/b.
# With a ~ b: k < 2a. Which we already knew (k = D^2*p - a^2 in [0, 2a]).
# So the condition is always satisfied. Good.

# Now the ACTUAL question: can we recover p from a, b, n?
# p = (a^2 + k) / D^2 where k is uniquely determined by:
# D^2 | (a^2 + k) AND (a^2+k) | D^4*n AND k in [0, 2a].
#
# Since D^2 | (a^2+k): k ≡ -a^2 (mod D^2), so k = (-a^2 % D^2) + m*D^2 for m >= 0.
# And k < 2a ~ 2^753, D^2 ~ 2^168, so m can range from 0 to ~2^585. Too many.
#
# BUT: (a^2+k) | D^4*n means p | n. So we need p to divide n.
# The divisors of n that are in range [a^2/D^2, (a+1)^2/D^2) are very few (likely just p itself).
#
# Factoring n directly in this range: impossible without factoring n.
#
# WAIT: I think the real solution is to use the EXACT isqrt computations to
# get the exact a and b, and then find p via a MODULAR INVERSE approach!
#
# Here's the trick: since (a^2+k) * (b^2+j) = D^4*n:
# a^2 * b^2 + a^2*j + b^2*k + k*j = D^4*n
# b^2*k + a^2*j = D^4*n - a^2*b^2 - k*j = C - k*j (where C = D^4*n - a^2*b^2)
#
# Since k*j <= 2a * 2b = 4ab and C = D^4*n - a^2*b^2:
# b^2*k + a^2*j = C (approximately, ignoring k*j)
# This is a LINEAR DIOPHANTINE EQUATION in k and j!
#
# Solutions: k = k0 + (a^2/g)*t, j = j0 - (b^2/g)*t for integer t,
# where g = gcd(a^2, b^2) and (k0, j0) is a particular solution.
#
# With additional constraints k in [0, 2a] and j in [0, 2b]:
# The unique solution within these bounds gives us k and j!
# (If the solution space modulo a^2/g gives just one valid solution.)
#
# Let me compute C = D^4*n - a^2*b^2:
C = D**4 * n - a**2 * b**2
print(f'C = D^4*n - a^2*b^2 bit length: {C.bit_length()}')
print(f'a^2 bit length: {(a**2).bit_length()}')
print(f'b^2 bit length: {(b**2).bit_length()}')

# The linear Diophantine equation: b^2*k + a^2*j = C
# (ignoring k*j for now)
# gcd(a^2, b^2) | C?
g = gmpy2.gcd(a**2, b**2)
print(f'gcd(a^2,b^2) = {g}')
print(f'C % g = {C % g}')

# For the full equation (a^2+k)(b^2+j) = D^4*n:
# Let X = a^2+k (= D^2*p) and Y = b^2+j (= D^2*q).
# X*Y = D^4*n.
# X is in [a^2, (a+1)^2) = [a^2, a^2+2a+1).
# Y is in [b^2, (b+1)^2) = [b^2, b^2+2b+1).
#
# Divisors of D^4*n in the range [a^2, a^2+2a]: those are the candidates for X = D^2*p.
#
# Since D^4*n = D^4*p*q, and X = D^2*p, the only divisors of D^4*n in [a^2, a^2+2a]
# that are multiples of D^2 are X = D^2*p and possibly D^2*q (if in range, unlikely).
#
# The ACTUAL approach to find X:
# X = D^4*n / Y where Y is in [b^2, b^2+2b].
# For Y = b^2, b^2+1, ..., b^2+2b:
# X = D^4*n // Y (integer division) -- but this may not be exact.
# We need X * Y = D^4*n exactly.
#
# Alternative: since X and Y are both related to factors of D^4*n:
# X = D^2*p where p | n.
# We need: gcd(X, D^4*n) = X, i.e., X | D^4*n.
# X | D^4*n iff p | n (assuming gcd(D,p)=1).
# So X = D^2 * (some factor of n).
#
# Factors of n in [a^2/D^2, (a+1)^2/D^2): this range has width 2a/D^2 ~ 2^585. Still too large.

# LAST RESORT APPROACH:
# The problem might actually be solvable with a DIFFERENT interpretation of the challenge.
# What if the challenge intends a MUCH simpler attack?
#
# Let me re-read the encryption:
# c_i = pow(x, 1337+b, n) * pow(r, 1337+1337, n) % n
# The POWER of r is 2*1337 = 2674 = 2*1337.
# The POWER of x is 1337+b = 1337 or 1338.
#
# To DECRYPT, we need Legendre(c_i, p).
# For Legendre, we only need p (a prime factor of n).
#
# From the hint, we can compute an APPROXIMATION of p.
# But to compute exact Legendre symbol, we need exact p.
#
# Unless... we can use the JACOBI symbol instead of Legendre?
# Jacobi(c_i, n) = Legendre(c_i, p) * Legendre(c_i, q).
# Since Legendre(c_i, p) = -1 or 1, and Legendre(c_i, q) = -1 or 1.
# We can't distinguish from Jacobi alone.
#
# BUT: if Legendre(c_i, p) = Legendre(c_i, q) (same sign), then Jacobi = +1.
# If they differ, Jacobi = -1.
# From the encryption: c_i = x^(1337+b) * r^2674 mod n.
# Legendre(c_i, p) = (-1)^(1337+b) * 1 = (-1)^(1337+b).
# Legendre(c_i, q) = (-1)^(1337+b) * 1 = (-1)^(1337+b) (same!).
#
# So Legendre(c_i, p) = Legendre(c_i, q) always! And Jacobi = Legendre^2 = 1. Always!
# That can't be right... Jacobi would always be 1 and give no information.
#
# Wait: Legendre(x, q) = -1 (given in challenge) AND Legendre(x, p) = -1 (given).
# So x is a non-residue mod both p and q.
# Legendre(x^(1337+b), p) = (-1)^(1337+b).
# Legendre(x^(1337+b), q) = (-1)^(1337+b).
# They're equal. So Jacobi(c_i, n) = Legendre(c_i,p) * Legendre(c_i,q) = ((-1)^(1337+b))^2 = 1.
#
# So the Jacobi symbol of c_i is ALWAYS 1, regardless of b. No information without p!
# We DEFINITELY need to factor n.

# Let me try a last-resort approach:
# Compute gcd(a, b) (gcd of the isqrt values).
# If gcd(a, b) = D * something, we might find p or q.
g_ab = gmpy2.gcd(a, b)
print(f'gcd(a, b) = {g_ab}')
print(f'gcd(a, b) bit length: {g_ab.bit_length()}')

# Hmm. Maybe gcd is large if a = D*isqrt(p) and b = D*isqrt(q) share factors?
# isqrt(D^2*p) is not simply D*isqrt(p) for non-perfect-square D^2*p.
