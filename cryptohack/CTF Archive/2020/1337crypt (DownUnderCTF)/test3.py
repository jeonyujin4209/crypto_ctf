import gmpy2
from mpmath import mp, sqrt as mpsqrt, floor as mpfloor, nint as mpnint

# Test with small primes to understand the correct approach
p_t, q_t, D_t = 1009, 1013, 63
n_t = p_t*q_t
a_t = int(gmpy2.isqrt(D_t**2*p_t))
b_t = int(gmpy2.isqrt(D_t**2*q_t))
print(f'a={a_t}, b={b_t}, a*b={a_t*b_t}')
K_t = int(gmpy2.isqrt(D_t**4*n_t))
print(f'isqrt(D^4*n)={K_t}, diff = {a_t*b_t - K_t}')

hint_t = a_t + b_t
print(f'hint_t={hint_t}')

# The key: compute a-b from hint and a*b
# (a-b)^2 = (a+b)^2 - 4*a*b = hint^2 - 4*a*b
print(f'(a-b)^2 = {(a_t-b_t)**2}')
print(f'hint^2-4*a*b = {hint_t**2 - 4*a_t*b_t}')

# We need a*b. Let's compute it as isqrt(D^4*n) + correction.
# a*b = D^2*sqrt(n) - D*(sqrt(p)*eq + sqrt(q)*ep) + ep*eq
# where ep = D*sqrt(p) - a (in [0,1)), eq = D*sqrt(q) - b (in [0,1))

# In the small example: a*b = 4012005, K_t = isqrt(D^4*n) = ?
# Let me compute properly:
print(f'D_t^4*n_t = {D_t**4*n_t}')
print(f'isqrt(D_t^4*n_t) = {K_t}')
# a*b = 4012005... wait the test showed a*b=4012005, K_t=4012651 (earlier).
# Hmm, so a*b < K_t, not a*b > K_t. Let me recheck.
print()

# Now for the REAL problem: is there a way to compute a*b exactly?
#
# INSIGHT: Let's compute a*b from hint and (a-b)!
# But we don't know a-b either.
#
# Actually: a-b = floor(D*sqrt(p)) - floor(D*sqrt(q)) = floor(D*(sqrt(p)-sqrt(q))) approximately.
#
# From hint = a+b and n = p*q, we can TRY to compute (a-b) as:
# sqrt(hint^2 - 4*D^2*sqrt(n)) approximately (where D^2*sqrt(n) = isqrt(D^4*n) approximately).
#
# For the test case: hint^2 = 4006^2 = 16048036
# 4*D^2*sqrt(n) = 4*3969*sqrt(1022117) = 4*3969*1010.998... = 4*3969*1010 + ...
# 4*isqrt(D^2*n) = 4*isqrt(3969*1022117) = 4*isqrt(4056804773) = 4*63693 = 254772
# hint^2 - 4*K = 16048036 - 4*4012651 = 16048036 - 16050604 = -2568. Negative!
#
# But (a-b)^2 = 16. So hint^2 - 4*a*b = 16. But hint^2 - 4*K = -2568.
# Correction: 4*(a*b - K) = -2568, a*b - K = -642... but a*b=4012005, K=4012651, diff=-646.
# Close to -642 (small rounding differences).
#
# For the ACTUAL problem: D^2*sqrt(n) = isqrt(D^4*n)/D^2... no, D^2*sqrt(n) = isqrt(D^4*n).
# Wait: isqrt(D^4*n) = floor(D^2*sqrt(n)). And a*b in [D^2*sqrt(n)-hint, D^2*sqrt(n)).
#
# For the small test: D_t=63, n_t=1022117.
# D_t^2*sqrt(n_t) = 3969*sqrt(1022117) = 3969*1010.998... ≈ 3969*1011 ≈ 4012659.
# a*b = 4012005 < D^2*sqrt(n) = 4012659. Difference = 654.
# hint_t = 4006 ~ D*(sqrt(p)+sqrt(q)) = 63*2022.05 = 63*63.18*32 ~ ...
# hint_t/D_t = 4006/63 = 63.58. sqrt(p)+sqrt(q) = sqrt(1009)+sqrt(1013) = 31.76+31.83 = 63.59.
# Hmm, 63/D = 1, so hint/D ~ sqrt(p)+sqrt(q) ~ 63.59. OK D=63, so hint ~ 63*63.59 = 4006.17, floor=4006.
#
# The point: for the EXACT small problem, can we recover a and b?
# We want a,b with a+b=4006 and a=floor(63*sqrt(1009)), b=floor(63*sqrt(1013)).
# a = floor(63*31.765..) = floor(2001.2) = 2001.
# b = 4006 - 2001 = 2005.
#
# So from hint and n alone: solve for a in (0, hint) such that:
# floor(sqrt(D^2*(n//(a^2/D^2+1)))) or similar = hint-a. Very circular.
#
# But in the mpmath approach: a_approx = floor(D*u) where u = sqrt(p)-approx.
# For the test: u = sqrt(1009) - approx ≈ 31.765, D*u = 63*31.765 ≈ 2001.2, floor=2001 = a_t. Correct!
#
# So the mpmath approach DOES give a_approx = a_t in the small case.
# For the large case: a_approx + b_approx = hint-1 (off by 1).
# This means: one of a_approx or b_approx is 1 less than the true value.
#
# TRY: for each of the two corrections (+1 to a or +1 to b), compute p and q.

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
v = (s - sqrtdisc) / 2

Du = mp.mpf(D) * u
Dv = mp.mpf(D) * v
a_approx = int(mpfloor(Du))
b_approx = int(mpfloor(Dv))

print(f'a_approx + b_approx - hint = {a_approx + b_approx - hint}')

# Case 1: a = a_approx+1, b = b_approx
# From a: D^2*p = a^2 + r1, r1 = (-a^2) mod D^2
# p = (a^2 + r1) / D^2

# But r1 has multiple possibilities: r1 = r1_base + k*D^2 for k=0,1,2,...
# where r1_base = (-a^2) mod D^2.
# p is uniquely determined as a factor of n in range [a^2/D^2, (a+1)^2/D^2).
#
# ALTERNATIVE: given a = isqrt(D^2*p), compute p as:
# p_candidates = {k : k divides n AND D^2 | (a^2 + r) for r=D^2*k - a^2}
# i.e., p_candidates = {k : k | n AND k*D^2 >= a^2 AND k*D^2 < (a+1)^2}
# i.e., p_candidates = {k : k | n AND a^2/D^2 <= k < (a+1)^2/D^2}
#
# For each a candidate, compute a^2/D^2 and search for divisors of n in that range.
# But finding divisors of n in a range is as hard as factoring n!
#
# UNLESS: n mod a^2 gives us something useful.
#
# Let me try: D^4 * n = (a^2 + r1) * (b^2 + r2) where r1 = D^2*p - a^2 > 0 small.
# (a^2 + r1) * (b^2 + r2) = D^4*n
#
# For a = a_approx+1, b = b_approx:
a_try1 = a_approx + 1
b_try1 = b_approx

# Check: is (a_try1^2 + r1) * (b_try1^2 + r2) = D^4*n for some small r1, r2?
# r1 = D^2*p - a_try1^2, r2 = D^2*q - b_try1^2
# Both should be in [0, D^2) approximately.
# But we can search: what is n mod a_try1 (using the formula)?

# Actually, think of it this way:
# if a = isqrt(D^2*p), then a^2 <= D^2*p < (a+1)^2.
# D^4*n / a^2 = D^2*q * (D^2*p/a^2) = D^2*q * (1 + r1/a^2) where r1/a^2 in [0, 1+2/a).
# For large a: D^4*n/a^2 ~ D^2*q.
# isqrt(D^4*n // a^2) would give approximately D*sqrt(q).

# Let me try: for a candidate a, compute q via floor(D*sqrt(n//(a^2//D^2+1))):
# p = ??, q = n/p. If a^2 ~ D^2*p, then p ~ a^2/D^2, so q ~ n*D^2/a^2.

# DIRECT APPROACH: iterate over a_approx, a_approx+1, a_approx+2:
for delta_a in range(-5, 6):
    a_cand = a_approx + delta_a
    if a_cand <= 0:
        continue
    b_cand = hint - a_cand
    if b_cand <= 0:
        continue
    # From a_cand: D^2*p is approximately a_cand^2.
    # a_cand^2 / D^2 should be close to p.
    # p must divide n. Let's compute floor(a_cand^2 / D^2) and check nearby values.
    p_est = a_cand**2 // D**2
    for dp in range(-1000, 1001):
        p_try = p_est + dp
        if p_try > 1 and n % p_try == 0:
            q_try = n // p_try
            # Verify: isqrt(D^2*p_try) = a_cand?
            a_check = int(gmpy2.isqrt(D**2 * p_try))
            b_check = int(gmpy2.isqrt(D**2 * q_try))
            if a_check + b_check == hint:
                print(f'FOUND! delta_a={delta_a}, dp={dp}')
                print(f'p = {p_try}')
                print(f'q = {q_try}')
                print(f'p*q==n: {p_try*q_try==n}')
                print(f'is_prime(p): {bool(gmpy2.is_prime(p_try))}')
                break
        else:
            p_try = None
    if p_try and n % p_try == 0:
        break

print('Search complete')
