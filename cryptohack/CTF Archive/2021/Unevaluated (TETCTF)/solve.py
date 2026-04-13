"""
Unevaluated (TETCTF 2021)

Complex DH over Z[i]/(p^2) where the group order is p*q*r.
Solve the DLP using Pohlig-Hellman over the three prime factors p, q, r.

Group: Z[i]/(n)* where n = p^2 and the order is p*q*r.
p ≡ 3 mod 4 → g generates a cyclic group of order p*q*r.

Steps:
1. Parse g, order=p*q*r, n=p^2, public_key
2. Solve DLP using Pohlig-Hellman:
   - Solve k mod p: h_p = g^(order/p), pk_p = pub^(order/p), BSGS
   - Solve k mod q: h_q = g^(order/q), pk_q = pub^(order/q), BSGS
   - Solve k mod r: h_r = g^(order/r), pk_r = pub^(order/r), BSGS
3. CRT to combine
4. Decrypt flag
"""
from math import gcd, isqrt
from Crypto.Cipher import AES
from collections import namedtuple

Complex = namedtuple("Complex", ["re", "im"])

def cmul(c1, c2, n):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % n,
        (c1.re * c2.im + c1.im * c2.re) % n,
    )

def cpow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = cmul(result, c, n)
        c = cmul(c, c, n)
        exp >>= 1
    return result

def cbsgs(g, h, order, n):
    """Baby-step giant-step for complex DLP: find k s.t. g^k = h in Z[i]/(n)"""
    m = isqrt(order) + 1
    # Baby steps: g^j for j in 0..m
    baby = {}
    gj = Complex(1, 0)
    for j in range(m):
        baby[(gj.re, gj.im)] = j
        gj = cmul(gj, g, n)
    # Giant steps: h * g^(-m*i)
    gm_inv = cpow(g, order - m, n)  # g^(-m) = g^(order-m)
    giant = h
    for i in range(m + 1):
        key = (giant.re, giant.im)
        if key in baby:
            k = i * m + baby[key]
            return k % order
        giant = cmul(giant, gm_inv, n)
    raise ValueError("DLP not found")

def crt(remainders, moduli):
    x, M = 0, 1
    for m in moduli:
        M *= m
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M

g = Complex(re=20878314020629522511110696411629430299663617500650083274468525283663940214962,
            im=16739915489749335460111660035712237713219278122190661324570170645550234520364)
order_full = 364822540633315669941067187619936391080373745485429146147669403317263780363306505857156064209602926535333071909491
n = 42481052689091692859661163257336968116308378645346086679008747728668973847769
pub = Complex(re=11048898386036746197306883207419421777457078734258168057000593553461884996107,
              im=34230477038891719323025391618998268890391645779869016241994899690290519616973)

encrypted_flag = b'\'{\xda\xec\xe9\xa4\xc1b\x96\x9a\x8b\x92\x85\xb6&p\xe6W\x8axC)\xa7\x0f(N\xa1\x0b\x05\x19@<T>L9!\xb7\x9e3\xbc\x99\xf0\x8f\xb3\xacZ:\xb3\x1c\xb9\xb7;\xc7\x8a:\xb7\x10\xbd\x07"\xad\xc5\x84'

# Factorize order = p * q * r
# From the source code comments, p satisfies specific conditions
# The generate_params function produces p ≡ 3 mod 4, p ≡ 2 mod 3 → q=(p-1)//2, r=(p+1)//12
# OR p ≡ 3 mod 4, p ≡ 1 mod 3... (not 2 mod 3) → q=(p-1)//6, r=(p+1)//4
# n = p^2, so p = isqrt(n)
p_n = isqrt(n)
assert p_n * p_n == n, "n is not a perfect square"
print(f"p = {p_n}")
print(f"p mod 4 = {p_n % 4}, p mod 3 = {p_n % 3}")

if p_n % 4 == 3 and p_n % 3 == 2:
    q_f = (p_n - 1) // 2
    r_f = (p_n + 1) // 12
else:
    q_f = (p_n - 1) // 6
    r_f = (p_n + 1) // 4

print(f"Checking factorization: order = {order_full}")
print(f"p*q*r = {p_n * q_f * r_f}")
assert p_n * q_f * r_f == order_full, "Factorization mismatch"
print(f"Confirmed: order = {p_n} * {q_f} * {r_f}")

# Pohlig-Hellman
factors = [p_n, q_f, r_f]
residues = []
for prime in factors:
    cofactor = order_full // prime
    g_sub = cpow(g, cofactor, n)
    h_sub = cpow(pub, cofactor, n)
    print(f"  BSGS for prime={prime} (sqrt={isqrt(prime)+1} steps)...", flush=True)
    k_i = cbsgs(g_sub, h_sub, prime, n)
    residues.append(k_i)
    print(f"  k mod {prime} = {k_i}")

k = crt(residues, factors)
print(f"\nRecovered k = {k}")

# Verify
assert cpow(g, k, n) == pub, "DLP verification failed"
print("DLP verified!")

# Decrypt flag
private_key_bytes = k.to_bytes(32, 'big')
flag = AES.new(private_key_bytes, AES.MODE_ECB).decrypt(encrypted_flag)
print("flag:", flag)
