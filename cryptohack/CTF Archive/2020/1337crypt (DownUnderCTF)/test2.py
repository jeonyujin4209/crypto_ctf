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

isqrt_p = int(mpfloor(u))
isqrt_q = int(mpfloor(v))
print(f'isqrt_p bits: {isqrt_p.bit_length()}')
print(f'isqrt_q bits: {isqrt_q.bit_length()}')

# p is in [isqrt_p^2, (isqrt_p+1)^2)
# q = n/p, so q is in [n/(isqrt_p+1)^2, n/isqrt_p^2)
# Similarly, p is in [n/(isqrt_q+1)^2, n/isqrt_q^2)
# The INTERSECTION of these two constraints gives us p very precisely!

p_lo1 = isqrt_p**2
p_hi1 = (isqrt_p+1)**2 - 1  # p < (isqrt_p+1)^2

p_lo2 = n // (isqrt_q+1)**2  # floor(n/(isqrt_q+1)^2) -- might need ceil
# Actually: p >= n/(isqrt_q+1)^2 iff p*(isqrt_q+1)^2 >= n iff ... not exact
# Let's just compute: p = n // q, and q is in [isqrt_q^2, isqrt_q^2+2*isqrt_q]
# So p = n // q is in [n//(isqrt_q^2+2*isqrt_q), n//isqrt_q^2]

p_lo = n // (isqrt_q**2 + 2*isqrt_q)
p_hi = n // isqrt_q**2

print(f'p range from isqrt_q bounds: [{p_lo.bit_length()} bits, {p_hi.bit_length()} bits]')
print(f'range size: {p_hi - p_lo}')

# Now intersect with p range from isqrt_p:
p_final_lo = max(p_lo, isqrt_p**2)
p_final_hi = min(p_hi, (isqrt_p+1)**2 - 1)
print(f'intersection p range: [{p_final_lo.bit_length()} bits, {p_final_hi.bit_length()} bits]')
print(f'intersection range size: {p_final_hi - p_final_lo}')

# If range size is small, we can brute force!
for p_cand in range(int(p_final_lo), int(p_final_hi)+1):
    if n % p_cand == 0:
        p = p_cand
        q = n // p_cand
        print(f'Found p = {p}')
        print(f'Found q = {q}')
        print(f'p*q == n: {p*q==n}')
        break
else:
    print('Not found in intersection range')
    print(f'p_final_lo: {p_final_lo}')
    print(f'p_final_hi: {p_final_hi}')
