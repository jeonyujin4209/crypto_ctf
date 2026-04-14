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
v = (s - sqrtdisc) / 2
Du = mp.mpf(D) * u
Dv = mp.mpf(D) * v
a_approx = int(mpfloor(Du))
b_approx = int(mpfloor(Dv))

print(f'a_approx + b_approx - hint = {a_approx + b_approx - hint}')

# Try both corrections
for (da, db) in [(1, 0), (0, 1)]:
    a = a_approx + da
    b = b_approx + db
    assert a + b == hint
    # Check: isqrt(D^4 * n // a^2) should be close to b
    # (since D^4*n / a^2 ~ D^2*q, and isqrt(D^2*q) = b)
    val = D**4 * n // a**2
    b_check = int(gmpy2.isqrt(val))
    print(f'  da={da},db={db}: b={b}, b_check={b_check}, diff={b-b_check}')

# KEY INSIGHT: If we iterate: start with approximate a0, compute b0=hint-a0,
# then compute a1 = isqrt(D^4*n // b0^2), then b1=hint-a1, etc.
# This should converge to the exact (a, b).

print()
print("Iterative approach:")
# Start with a_approx
a_curr = a_approx + 1  # try the more likely correction
for iteration in range(10):
    b_curr = hint - a_curr
    if b_curr <= 0:
        break
    # Compute new a from b_curr
    a_new = int(gmpy2.isqrt(D**4 * n // b_curr**2))
    print(f'  iter {iteration}: a={a_curr}, b={b_curr}, a_new={a_new}, diff={a_new-a_curr}')
    if a_new == a_curr:
        print(f'  Converged!')
        break
    a_curr = a_new

# Check if the final a,b give us p,q:
b_final = hint - a_curr
print(f'Final: a={a_curr}, b={b_final}')
# p = D^2*p / D^2. D^2*p is in [a^2, (a+1)^2).
# Find p by: D^2*p ≡ 0 (mod 1), i.e., just p | n.
# p = (D^2*p) / D^2 where D^2*p = a^2 + r, r = (-a^2) mod D^2.
r = (-a_curr**2) % D**2
D2p = a_curr**2 + r
if D2p % D**2 == 0:
    p_cand = D2p // D**2
    if n % p_cand == 0:
        q_cand = n // p_cand
        print(f'Found p={p_cand} (first 30 digits: {str(p_cand)[:30]})')
        print(f'is_prime(p): {bool(gmpy2.is_prime(p_cand))}')
    else:
        print(f'p_cand = {p_cand} does not divide n')
        print(f'n % p_cand = {n % p_cand}')
else:
    print(f'D2p is not divisible by D^2: D2p % D^2 = {D2p % D**2}')

# What is r?
print(f'r = (-a^2) mod D^2 = {r}')
print(f'r bit length: {r.bit_length()}')
D2 = D**2
print(f'D^2 bit length: {D2.bit_length()}')
# r should be small (< D^2 ~ 2^168). If r is indeed < D^2, then D2p = a^2 + r is uniquely
# the SMALLEST multiple of D^2 that is > a^2. But is that equal to D^2*p?
# D^2*p = a^2 + r1 where r1 = D^2*p - a^2.
# The smallest multiple of D^2 above a^2 is a^2 + ((-a^2) mod D^2) = a^2 + r (what we computed).
# This EQUALS D^2*p only if D^2*p - a^2 = r = (-a^2) mod D^2.
# i.e., D^2*p ≡ 0 (mod D^2) which is always true (p is integer).
# AND D^2*p - a^2 = r = smallest positive value ≡ -a^2 (mod D^2).
# i.e., D^2*p - a^2 < D^2.
#
# Is D^2*p - a^2 < D^2? i.e., D^2*(p-1) < a^2 <= D^2*p.
# a = isqrt(D^2*p) means a^2 <= D^2*p < (a+1)^2.
# D^2*p - a^2 in [0, 2a] (since (a+1)^2 - a^2 = 2a+1 and D^2*p < (a+1)^2).
# Is 2a < D^2? No! 2a ~ 2^753 >> D^2 ~ 2^168.
# So D^2*p - a^2 can be as large as ~2*a >> D^2.
# r = (-a^2) mod D^2 gives the SMALLEST possible r, but actual r = D^2*p - a^2 > r.
# The formula FAILS for large D.
print()
print("Formula p = (a^2 + r_min)/D^2 FAILS because r_actual > r_min for large D.")
print("Need a completely different approach!")
