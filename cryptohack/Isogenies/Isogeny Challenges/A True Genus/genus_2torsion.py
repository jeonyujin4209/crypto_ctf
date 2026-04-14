"""
A True Genus - Genus character via unique 2-torsion point.

Key insight:
- p+1 = 2 * prod(ls) where prod(ls) is odd
- So 4 does NOT divide p+1, meaning E(F_p) has a UNIQUE 2-torsion point T
- T = (x_T, 0) where x_T is the UNIQUE root of x³ + a4*x + a6 in F_p
- The genus character χ(E) = Legendre(x_T, p) might be multiplicative

This is related to the Castryck-Sotáková-Vercauteren genus theory attack.
"""
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import json
from math import prod

def primes_between(lo, hi):
    sieve = [True]*(hi+1); sieve[0]=sieve[1]=False
    for i in range(2,int(hi**.5)+1):
        if sieve[i]:
            for j in range(i*i,hi+1,i): sieve[j]=False
    return [x for x in range(lo,hi+1) if sieve[x]]

ls = primes_between(3,112) + [139]
p = 2*prod(ls) - 1
print(f"p = {p}")
print(f"p bits = {p.bit_length()}, p%4={p%4}, p%8={p%8}")
print(f"p+1 = 2 * prod(ls), prod(ls) odd? {prod(ls)%2}")

# ── Polynomial arithmetic in F_p[x] ──────────────────────────────────────
def poly_mul(a, b):
    """Multiply polynomials a, b represented as coeff lists (LSB first)."""
    if not a or not b: return []
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            result[i+j] = (result[i+j] + ai * bj) % p
    return result

def poly_mod(a, f):
    """Reduce polynomial a mod f (f is monic of degree 3)."""
    a = list(a)
    df = len(f) - 1  # degree of f = 3
    while len(a) - 1 >= df:
        if a[-1] == 0:
            a.pop(); continue
        lead = a[-1]
        deg_a = len(a) - 1
        shift = deg_a - df
        for i, fi in enumerate(f):
            a[i + shift] = (a[i + shift] - lead * fi) % p
        while a and a[-1] == 0:
            a.pop()
    return a if a else [0]

def poly_pow_mod(base_poly, exp, mod_poly):
    """Compute base_poly^exp mod mod_poly in F_p[x]."""
    result = [1]  # = 1 (constant polynomial)
    base = list(base_poly)
    while exp > 0:
        if exp & 1:
            result = poly_mod(poly_mul(result, base), mod_poly)
        base = poly_mod(poly_mul(base, base), mod_poly)
        exp >>= 1
    return result

def poly_gcd(a, b):
    """GCD of polynomials over F_p using Euclidean algorithm."""
    while b and not all(c == 0 for c in b):
        # a = q*b + r, compute r = a mod b
        a = list(a); b = list(b)
        while a and a[-1] == 0: a.pop()
        while b and b[-1] == 0: b.pop()
        if not b: break
        if len(a) < len(b): a, b = b, a
        if len(a) == len(b) and len(a) == 0: break
        # Long division: a / b = q + r/b
        db = len(b) - 1
        while len(a) - 1 >= db:
            if a[-1] == 0: a.pop(); continue
            lead = a[-1] * pow(b[-1], p-2, p) % p  # leading coeff of quotient
            shift = len(a) - 1 - db
            for i, bi in enumerate(b):
                a[i + shift] = (a[i + shift] - lead * bi) % p
            while a and a[-1] == 0: a.pop()
        a, b = b, a if a else [0]
    return a

def find_fp_root_cubic(a4, a6):
    """
    Find the unique F_p root of x^3 + a4*x + a6 = 0.
    Uses: gcd(x^p - x, f(x)) in F_p[x].
    f = [a6, a4, 0, 1] (coeffs of 1 + a4*x + 0*x^2 + 1*x^3, i.e., a6 + a4*x + x^3)
    """
    # f(x) = x^3 + a4*x + a6 (monic, degree 3)
    f = [a6 % p, a4 % p, 0, 1]  # [const, x, x^2, x^3]

    # Compute x^p mod f(x)
    x_poly = [0, 1]  # polynomial x
    xp_mod_f = poly_pow_mod(x_poly, p, f)

    # Compute x^p - x mod f
    xp_minus_x = list(xp_mod_f)
    if len(xp_minus_x) < 2:
        xp_minus_x += [0] * (2 - len(xp_minus_x))
    xp_minus_x[1] = (xp_minus_x[1] - 1) % p

    # gcd(x^p - x, f) = factor of f with F_p roots
    g = poly_gcd(xp_minus_x, f)

    # If g has degree 1: g = [b, 1] → root = -b/1 = -b mod p
    while g and g[-1] == 0: g.pop()
    if len(g) == 2:
        # g = b + x → root = -b
        return (-g[0]) * pow(g[1], p-2, p) % p
    elif len(g) == 4:
        # g = f (no F_p root, shouldn't happen for CSIDH curves)
        print(f"WARNING: no F_p root found for a4={a4}, a6={a6}")
        return None
    else:
        # Unexpected degree
        print(f"WARNING: unexpected gcd degree {len(g)-1} for a4={a4}, a6={a6}")
        return None

def legendre(a, l):
    a = a % l
    if a == 0: return 0
    return 1 if pow(a, (l-1)//2, l) == 1 else -1

# ── Load challenge data ────────────────────────────────────────────────────
with open(r'C:\Users\UserK\Documents\hackerone\program\crypto_ctf\cryptohack\Isogenies\Isogeny Challenges\A True Genus\output.txt') as f:
    data = json.load(f)
iv_hex = data['iv']; ct_hex = data['ct']
challenges = data['challenge_data']
print(f"Loaded {len(challenges)} challenges\n")

# ── Test: verify 2-torsion point satisfies curve equation ─────────────────
print("=== Checking 2-torsion computation ===")
ch = challenges[0]
for key in ['EA', 'EB', 'EC']:
    a4 = ch[key]['a4'][0]; a6 = ch[key]['a6'][0]
    xT = find_fp_root_cubic(a4, a6)
    if xT is not None:
        check = (pow(xT, 3, p) + a4*xT + a6) % p
        print(f"  {key}: x_T = {xT}, check f(x_T) = {check} (should be 0)")
print()

# ── Compute genus character for all challenges ────────────────────────────
print("=== Computing genus character χ(E) = Legendre(x_T, p) ===")
bits = []
for i, ch in enumerate(challenges):
    chars = {}
    for key in ['EA', 'EB', 'EC']:
        a4 = ch[key]['a4'][0]; a6 = ch[key]['a6'][0]
        xT = find_fp_root_cubic(a4, a6)
        chars[key] = legendre(xT, p) if xT is not None else 0

    ga, gb, gc = chars['EA'], chars['EB'], chars['EC']
    if ga == 0 or gb == 0 or gc == 0:
        bits.append(None)
    elif gc == ga * gb:
        bits.append(1)
    else:
        bits.append(0)

print(f"  Predictions: {bits[:20]}...")
print(f"  None: {bits.count(None)}, 1: {bits.count(1)}, 0: {bits.count(0)}")
print()

# ── Try decryption ─────────────────────────────────────────────────────────
def try_decrypt(bit_list, name):
    # Replace None with 0
    blist = [b if b is not None else 0 for b in bit_list]
    secret = sum(b * (1 << i) for i, b in enumerate(blist))
    print(f"  {name}: SECRET = {secret} ({secret.bit_length()} bits)")
    try:
        secret_bytes = secret.to_bytes(8, 'big')
    except OverflowError:
        print(f"  {name}: secret too large!")
        return
    key = SHA256.new(data=secret_bytes).digest()[:32]
    try:
        ct = bytes.fromhex(ct_hex); iv = bytes.fromhex(iv_hex)
        flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        print(f"  *** FLAG: {flag.decode()} ***")
    except Exception as e:
        print(f"  {name}: decrypt failed: {e}")

print("=== Attempting decryption ===")
try_decrypt(bits, "2-torsion Legendre")
try_decrypt([1-b if b is not None else 0 for b in bits], "inverted 2-torsion")

# ── Also try: Legendre(x_T, l_i) for each l_i ────────────────────────────
print()
print("=== Testing: product(Legendre(x_T, l_i)) for l_i in ls ===")
bits2 = []
for ch in challenges:
    chars = {}
    for key in ['EA','EB','EC']:
        a4 = ch[key]['a4'][0]; a6 = ch[key]['a6'][0]
        xT = find_fp_root_cubic(a4, a6)
        if xT is None:
            chars[key] = 0
        else:
            r = 1
            for l in ls:
                r *= legendre(xT, l)
            chars[key] = r
    ga, gb, gc = chars['EA'], chars['EB'], chars['EC']
    if ga == 0 or gb == 0 or gc == 0:
        bits2.append(None)
    elif gc == ga*gb:
        bits2.append(1)
    else:
        bits2.append(0)

print(f"  Predictions: {bits2[:20]}...")
print(f"  None: {bits2.count(None)}, 1: {bits2.count(1)}, 0: {bits2.count(0)}")
try_decrypt(bits2, "2-torsion * product Legendre(x_T, l_i)")
