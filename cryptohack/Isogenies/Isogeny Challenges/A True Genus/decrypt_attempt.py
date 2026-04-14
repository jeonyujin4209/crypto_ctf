"""
Try to decrypt the A True Genus flag using predicted bits from different genus characters.
"""
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import json
from math import prod

def primes_between(lo, hi):
    sieve = [True] * (hi+1); sieve[0] = sieve[1] = False
    for i in range(2, int(hi**0.5)+1):
        if sieve[i]:
            for j in range(i*i, hi+1, i): sieve[j] = False
    return [x for x in range(lo, hi+1) if sieve[x]]

ls = primes_between(3, 112) + [139]
p = 2 * prod(ls) - 1

def legendre(a, l):
    a = a % l
    if a == 0: return 0
    return 1 if pow(a, (l-1)//2, l) == 1 else -1

with open(r'C:\Users\UserK\Documents\hackerone\program\crypto_ctf\cryptohack\Isogenies\Isogeny Challenges\A True Genus\output.txt') as f:
    data = json.load(f)
iv_hex = data['iv']; ct_hex = data['ct']
challenges = data['challenge_data']

def fp2_mul(x, y):
    a1, b1 = x; a2, b2 = y
    return ((a1*a2 - 3*b1*b2) % p, (a1*b2 + a2*b1) % p)
def fp2_add(x, y): return ((x[0]+y[0]) % p, (x[1]+y[1]) % p)
def fp2_inv(x):
    a, b = x; norm = (a*a + 3*b*b) % p; ni = pow(norm, p-2, p)
    return (a*ni % p, (-b*ni) % p)
def fp2_pow(x, n):
    result = (1, 0); base = x
    while n > 0:
        if n & 1: result = fp2_mul(result, base)
        base = fp2_mul(base, base); n >>= 1
    return result
def j_inv(a4, a6):
    a4_3 = fp2_pow(tuple(a4), 3)
    num4 = fp2_mul((4,0), a4_3)
    j1728 = fp2_mul((1728,0), num4)
    a6_2 = fp2_pow(tuple(a6), 2)
    d2 = fp2_mul((27,0), a6_2)
    denom = fp2_add(num4, d2)
    return fp2_mul(j1728, fp2_inv(denom))

def try_decrypt(bits_list, name, byteorder='big'):
    """Try to decrypt using bits as SECRET bits (LSB first)."""
    secret = sum(b * (1 << i) for i, b in enumerate(bits_list))
    try:
        secret_bytes = secret.to_bytes(8, byteorder)
    except OverflowError:
        print(f"  {name}: secret too large for 8 bytes ({secret.bit_length()} bits)")
        return None
    key = SHA256.new(data=secret_bytes).digest()[:32]
    try:
        ct = bytes.fromhex(ct_hex)
        iv = bytes.fromhex(iv_hex)
        flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        print(f"  [{name}] FLAG: {flag}")
        return flag
    except Exception as e:
        print(f"  {name}: decrypt failed ({e})")
        return None

# Compute genus character predictions
# Test A: Legendre(j[0], p)
# Test B: Legendre(a6[0], p)
# Test C: Legendre(a4[0], p)

bits_j = []; bits_a6 = []; bits_a4 = []
for ch in challenges:
    ja = j_inv(ch['EA']['a4'], ch['EA']['a6'])
    jb = j_inv(ch['EB']['a4'], ch['EB']['a6'])
    jc = j_inv(ch['EC']['a4'], ch['EC']['a6'])

    for bits_list, key_fn in [(bits_j, lambda ch, X: j_inv(ch[X]['a4'], ch[X]['a6'])[0]),
                               (bits_a6, lambda ch, X: ch[X]['a6'][0]),
                               (bits_a4, lambda ch, X: ch[X]['a4'][0])]:
        ga = legendre(int(key_fn(ch, 'EA')), p)
        gb = legendre(int(key_fn(ch, 'EB')), p)
        gc = legendre(int(key_fn(ch, 'EC')), p)
        if ga == 0 or gb == 0 or gc == 0:
            bits_list.append(0)  # treat as 0
        elif gc == ga * gb:
            bits_list.append(1)
        else:
            bits_list.append(0)

print(f"Predicted SECRET bits (LSB first):")
print(f"  Test j   (25 ones): {bits_j}")
print(f"  Test a6  (30 ones): {bits_a6}")
print(f"  Test a4  (25 ones): {bits_a4}")
print()

print("Attempting decryption...")
for name, bits in [("j", bits_j), ("a6", bits_a6), ("a4", bits_a4)]:
    try_decrypt(bits, f"Legendre({name}, p)")

# Also try with the negated bits (complement: swap 0s and 1s)
print()
print("Attempting with inverted bits (swap 0<->1):")
for name, bits in [("j", bits_j), ("a6", bits_a6), ("a4", bits_a4)]:
    inv_bits = [1-b for b in bits]
    try_decrypt(inv_bits, f"~Legendre({name}, p)")

# Try assuming the secret is direct from a 64-bit random
# The ZZ(SECRET).bits() in Sage returns bits of secret from LSB
# For a 64-bit value with some leading bits 0, len(bits) < 64
# But the challenge data has exactly 63 entries, so secret had exactly 63 bits
print()
print(f"Note: 63 challenges → SECRET had 63 bits in ZZ().bits()")
print(f"This means SECRET has exactly 63 bits: bit[62]=1 (MSB) always")
