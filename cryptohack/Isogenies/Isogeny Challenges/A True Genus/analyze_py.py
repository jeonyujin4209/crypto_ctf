"""
A True Genus - Pure Python genus theory analysis.

Hypothesis: for each CSIDH prime l in ls, the Legendre symbol (j(E) / l)
where j ∈ F_p is the genus character, and it satisfies:
    genus(shared) = genus(EA) * genus(EB)

This allows distinguishing the real shared secret from a random curve.
"""
import json, sys
from math import prod, sqrt, ceil, log2

# ── F_{p^2} arithmetic ────────────────────────────────────────────────────
# w^2 = -3 (modulus [3, 0, 1] → w^2 + 3 = 0)

def primes_below(n):
    sieve = list(range(n))
    for i in range(2, int(n**0.5)+1):
        if sieve[i]:
            for j in range(i*i, n, i):
                sieve[j] = 0
    return [x for x in sieve[2:] if x]

ls = primes_below(112) + [139]   # primes 3..111 + 139? Let me check
# Actually primes(3, 112) in Sage returns primes from 3 to 112 inclusive
ls = [x for x in primes_below(113) if x >= 3]  # primes 3..112 (inclusive)
# Now the ls from source includes 139 separately
ls = ls + [139]

p = 2 * prod(ls) - 1
print(f"p bits: {p.bit_length()}")
print(f"len(ls) = {len(ls)}")
print(f"ls = {ls}")
print(f"p % 4 = {p % 4}")
print(f"p % 3 = {p % 3}")

# F_{p^2} element: (a, b) represents a + b*w where w^2 = -3 mod p
def fp2_mul(x, y):
    a1, b1 = x; a2, b2 = y
    # (a1 + b1*w)(a2 + b2*w) = (a1*a2 - 3*b1*b2) + (a1*b2 + a2*b1)*w
    return ((a1*a2 - 3*b1*b2) % p, (a1*b2 + a2*b1) % p)

def fp2_add(x, y):
    return ((x[0]+y[0]) % p, (x[1]+y[1]) % p)

def fp2_sub(x, y):
    return ((x[0]-y[0]) % p, (x[1]-y[1]) % p)

def fp2_inv(x):
    a, b = x
    norm = (a*a + 3*b*b) % p
    norm_inv = pow(norm, p-2, p)
    return (a * norm_inv % p, (-b * norm_inv) % p)

def fp2_div(x, y):
    return fp2_mul(x, fp2_inv(y))

def fp2_pow(x, n):
    result = (1, 0)
    base = x
    while n > 0:
        if n & 1:
            result = fp2_mul(result, base)
        base = fp2_mul(base, base)
        n >>= 1
    return result

# j-invariant of y^2 = x^3 + a4*x + a6 over F_{p^2}
def j_invariant(a4, a6):
    # j = 1728 * (4*a4^3) / (4*a4^3 + 27*a6^2)
    a4_fp2 = tuple(a4)
    a6_fp2 = tuple(a6)
    num = fp2_pow(a4_fp2, 3)  # a4^3
    num = fp2_mul((4, 0), num)  # 4*a4^3
    j1728 = fp2_mul((1728, 0), num)
    denom_part1 = num  # 4*a4^3
    a6sq = fp2_pow(a6_fp2, 2)
    denom_part2 = fp2_mul((27, 0), a6sq)  # 27*a6^2
    denom = fp2_add(denom_part1, denom_part2)
    return fp2_div(j1728, denom)

def legendre(a, l):
    """Legendre symbol (a/l) for prime l"""
    a = a % l
    if a == 0:
        return 0
    return 1 if pow(a, (l-1)//2, l) == 1 else -1

# ── Load challenge data ────────────────────────────────────────────────────
with open(r'C:\Users\UserK\Documents\hackerone\program\crypto_ctf\cryptohack\Isogenies\Isogeny Challenges\A True Genus\output.txt') as f:
    data = json.load(f)

iv = data['iv']
ct = data['ct']
challenges = data['challenge_data']
print(f"\nLoaded {len(challenges)} challenges\n")

# ── Compute j-invariants for all challenges ────────────────────────────────
print("Computing j-invariants...")
j_challenges = []
for i, ch in enumerate(challenges):
    ja = j_invariant(ch['EA']['a4'], ch['EA']['a6'])
    jb = j_invariant(ch['EB']['a4'], ch['EB']['a6'])
    jc = j_invariant(ch['EC']['a4'], ch['EC']['a6'])
    j_challenges.append((ja, jb, jc))

# Check if j-invariants are in Fp (b-component = 0)
in_fp_count = sum(1 for ja, jb, jc in j_challenges
                   if ja[1] == 0 and jb[1] == 0 and jc[1] == 0)
print(f"J-invariants all in Fp: {in_fp_count}/{len(challenges)}")

# Print first few
for i in range(3):
    ja, jb, jc = j_challenges[i]
    print(f"  Challenge {i}: j(EA)=({ja[0]%100},{ja[1]%100}), j(EB)=({jb[0]%100},{jb[1]%100}), j(EC)=({jc[0]%100},{jc[1]%100})")

print()
# ── Test genus character: χ_l(E) = Legendre(j(E)[0], l) ────────────────────
# For each prime l in ls, check if this is multiplicative:
#   χ_l(shared) == χ_l(EA) * χ_l(EB)
# We don't know which bit is 1/0, but we can check CONSISTENCY:
# If our character is right, then for each challenge there are exactly 2 options:
# Either χ(EC) == χ(EA)*χ(EB) (bit=1) or χ(EC) != χ(EA)*χ(EB) (bit=0)
# And this should be CONSISTENT across all primes l

print("=== Testing genus character: Legendre(j[0], l) ===")
bits_by_char = {}  # l -> [bit for each challenge]

for l in ls[:5]:  # Start with first 5 primes
    bits = []
    for ja, jb, jc in j_challenges:
        ga = legendre(int(ja[0]), l)
        gb = legendre(int(jb[0]), l)
        gc = legendre(int(jc[0]), l)
        if ga == 0 or gb == 0 or gc == 0:
            bits.append(None)
        elif gc == ga * gb:
            bits.append(1)  # EC matches shared formula
        else:
            bits.append(0)
    bits_by_char[l] = bits
    print(f"  l={l}: bits[:10] = {bits[:10]}")

print()
# ── Check consistency across primes ────────────────────────────────────────
print("Checking consistency of bit predictions across primes:")
bit_predictions = []
for i in range(len(challenges)):
    votes = [bits_by_char[l][i] for l in ls[:5] if bits_by_char[l][i] is not None]
    # All primes should agree on the bit
    if votes:
        unique = list(set(votes))
        consistent = len(unique) == 1
        bit_predictions.append(votes[0] if consistent else None)
    else:
        bit_predictions.append(None)

print(f"Consistent predictions: {sum(1 for b in bit_predictions if b is not None)}/{len(bit_predictions)}")
print(f"First 20 bits: {bit_predictions[:20]}")
print()

# ── Try alternative: use a4[0] instead of j[0] ────────────────────────────
print("=== Testing genus character: Legendre(a4[0], l) ===")
bits_a4 = {}
for l in ls[:5]:
    bits = []
    for ch in challenges:
        a4a = ch['EA']['a4'][0]; a4b = ch['EB']['a4'][0]; a4c = ch['EC']['a4'][0]
        ga = legendre(a4a, l)
        gb = legendre(a4b, l)
        gc = legendre(a4c, l)
        if ga == 0 or gb == 0 or gc == 0:
            bits.append(None)
        elif gc == ga * gb:
            bits.append(1)
        else:
            bits.append(0)
    bits_a4[l] = bits
    print(f"  l={l}: bits[:10] = {bits[:10]}")

# ── Try: use a6[0] ────────────────────────────────────────────────────────
print()
print("=== Testing genus character: Legendre(a6[0], l) ===")
bits_a6 = {}
for l in ls[:5]:
    bits = []
    for ch in challenges:
        a6a = ch['EA']['a6'][0]; a6b = ch['EB']['a6'][0]; a6c = ch['EC']['a6'][0]
        ga = legendre(a6a, l)
        gb = legendre(a6b, l)
        gc = legendre(a6c, l)
        if ga == 0 or gb == 0 or gc == 0:
            bits.append(None)
        elif gc == ga * gb:
            bits.append(1)
        else:
            bits.append(0)
    bits_a6[l] = bits
    print(f"  l={l}: bits[:10] = {bits[:10]}")

# ── If we found the character, check if ALL primes agree ──────────────────
print()
print("=== Checking if j[0] Legendre symbol is consistent across ALL ls ===")
all_bits_j = []
for i, (ja, jb, jc) in enumerate(j_challenges):
    votes = []
    for l in ls:
        ga = legendre(int(ja[0]), l)
        gb = legendre(int(jb[0]), l)
        gc = legendre(int(jc[0]), l)
        if ga != 0 and gb != 0 and gc != 0:
            votes.append(1 if gc == ga * gb else 0)
    if votes:
        ones = votes.count(1)
        zeros = votes.count(0)
        all_bits_j.append((ones, zeros, ones > zeros))
    else:
        all_bits_j.append((0, 0, None))

print("Challenge: (votes_for_1, votes_for_0, predicted_bit)")
for i, (o, z, b) in enumerate(all_bits_j[:10]):
    print(f"  Challenge {i}: {o} votes for 1, {z} votes for 0, predicted: {b}")

# Compute predicted bits
predicted = [b for _, _, b in all_bits_j if b is not None]
print(f"\n{len(predicted)} predictions made")
final_bits = [b for _, _, b in all_bits_j]
print(f"Predicted bits: {final_bits}")
