import gmpy2
from mpmath import mp, sqrt as mpsqrt, floor as mpfloor, ceil as mpceil

path = 'C:/Users/UserK/Documents/hackerone/program/crypto_ctf/cryptohack/CTF Archive/2020/1337crypt (DownUnderCTF)/output.txt'
with open(path) as f:
    lines = f.read().strip().split('\n')
hint = int(lines[0].split(' = ')[1])
D    = int(lines[1].split(' = ')[1])
n    = int(lines[2].split(' = ')[1])

# Compute isqrt_p from mpmath with high precision
mp.prec = 3000
s = mp.mpf(hint) / mp.mpf(D)
t = mpsqrt(mp.mpf(n))
disc = s*s - 4*t
sqrtdisc = mpsqrt(disc)
u = (s + sqrtdisc) / 2  # approximately sqrt(p)

isqrt_p = int(mpfloor(u))
print(f'isqrt_p bit length: {isqrt_p.bit_length()}')

# q is approximately n // isqrt_p^2
q_approx = n // isqrt_p**2
print(f'q_approx bit length: {q_approx.bit_length()}')
print(f'n % q_approx = {n % q_approx}')
print(f'n % (q_approx-1) = {n % (q_approx-1)}')
print(f'n % (q_approx+1) = {n % (q_approx+1)}')

# Try a wider range
found = False
for delta in range(-100, 101):
    q_try = q_approx + delta
    if q_try > 1 and n % q_try == 0:
        q = q_try
        p = n // q_try
        print(f'Found q at delta={delta}!')
        print(f'p bit length: {p.bit_length()}')
        print(f'q bit length: {q.bit_length()}')
        print(f'p*q==n: {p*q==n}')
        print(f'is_prime(p): {bool(gmpy2.is_prime(p))}')
        print(f'is_prime(q): {bool(gmpy2.is_prime(q))}')
        found = True
        break

if not found:
    print('Not found in range -100..100')
    # Calculate how far off we might be
    v = (s - sqrtdisc) / 2  # approximately sqrt(q)
    isqrt_q = int(mpfloor(v))
    print(f'isqrt_q bit length: {isqrt_q.bit_length()}')
    print(f'isqrt_p + isqrt_q = {isqrt_p + isqrt_q}')
    print(f'hint = {hint}')
    print(f'hint - (isqrt_p + isqrt_q) = {hint - (isqrt_p + isqrt_q)}')

    # Try q from isqrt_q
    q2_approx = isqrt_q**2
    print(f'q2_approx from isqrt_q^2 bit length: {q2_approx.bit_length()}')

    # Try using exact integer computation
    # hint = isqrt(D^2*p) + isqrt(D^2*q)
    # If we compute a = isqrt(D^2*p) exactly via mpmath, then b = hint - a
    # and p = ceil(a^2/D^2)... no wait that's wrong.

    # Actually: p is a divisor of n. Let's try to compute a = isqrt(D^2*p) from mpmath
    # then search for the actual a that satisfies both conditions.

    # From mpmath: D*u approximates a = isqrt(D^2*p)
    Du = mp.mpf(D) * u
    a_approx = int(mpfloor(Du))
    print(f'a_approx bit length: {a_approx.bit_length()}')

    # For the exact a: isqrt(D^2*p) + isqrt(D^2*(n/p)) = hint
    # a = isqrt(D^2*p) is the floor of D*sqrt(p)
    # b = hint - a = isqrt(D^2*q)
    #
    # We need to find integer a such that:
    # a^2 <= D^2*p and (hint-a)^2 <= D^2*(n/p) < (hint-a+1)^2
    # where p | n.
    #
    # This is equivalent to finding p | n such that isqrt(D^2*p) + isqrt(D^2*q) = hint.
    # Binary search for p:

    print()
    print('Trying binary search approach...')
    # f(p) = isqrt(D^2*p) + isqrt(D^2*(n//p))
    # We want f(p) = hint, with p being a prime divisor of n.
    #
    # For binary search: note that f(p) is roughly D*(sqrt(p)+sqrt(n/p))
    # which decreases as p approaches sqrt(n) and increases away from it.
    # But we need p | n.

    # Let's compute f for a_approx based p:
    for delta in range(-1000, 1001):
        a_try = a_approx + delta
        if a_try <= 0:
            continue
        # From a_try, estimate p: p is in range [ceil(a_try^2/D^2), ...]
        # Too many candidates.
        pass

    print('Binary search in a-space too slow.')
    print()
    print('Trying: use hint to narrow down p+q, then solve quadratic.')
    print('hint^2/D^2 approx = (p+q) + 2*sqrt(n) + floor-corrections')
    hint_sq_over_D2 = mp.mpf(hint)**2 / mp.mpf(D)**2
    pq_sum_approx = hint_sq_over_D2 - 2*t
    print(f'pq_sum_approx = {int(pq_sum_approx)}')
    pq_sum_int = int(pq_sum_approx)
    print(f'pq_sum_int bit length: {pq_sum_int.bit_length()}')

    # Try p+q ≈ pq_sum_int, solve x^2 - (p+q)*x + n = 0
    for delta_pq in range(-10000, 10001):
        pq_try = pq_sum_int + delta_pq
        # Discriminant = pq_try^2 - 4*n
        disc2 = pq_try*pq_try - 4*n
        if disc2 < 0:
            continue
        sqrt_disc2 = int(gmpy2.isqrt(disc2))
        if sqrt_disc2 * sqrt_disc2 == disc2:
            # Perfect square! Found p+q.
            p_candidate = (pq_try + sqrt_disc2) // 2
            q_candidate = (pq_try - sqrt_disc2) // 2
            if p_candidate * q_candidate == n:
                print(f'Found p+q at delta={delta_pq}!')
                print(f'p = {p_candidate}')
                print(f'q = {q_candidate}')
                break
    else:
        print('p+q search failed in range -10000..10000')
