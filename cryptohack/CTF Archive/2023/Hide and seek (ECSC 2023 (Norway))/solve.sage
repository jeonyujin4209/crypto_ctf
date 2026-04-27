"""
Hide and seek (ECSC 2023, Norway)

Vulnerability:
  Given 42 samples (a_i, b_i, R_i) with R_i = a_i*P + b_i*Q where Q = FLAG*P,
  we can take any two samples to LINEARLY recover P (and Q):

    b_1*R_0 - b_0*R_1 = (b_1*a_0 - b_0*a_1) * P
    a_0*R_1 - a_1*R_0 = (a_0*b_1 - a_1*b_0) * Q

  So P, Q are recovered modulo the group order via scalar inversion.

  Then FLAG = log_P(Q). The curve order is FULLY smooth (all factors ~35-bit),
  so Pohlig-Hellman / Sage's discrete_log on the elliptic curve solves it in seconds.
"""
def long_to_bytes(n):
    n = int(n)
    L = (n.bit_length() + 7) // 8
    return n.to_bytes(L, 'big')

p = 1789850433742566803999659961102071018708588095996784752439608585988988036381340404632423562593
a = 62150203092456938230366891668382702110196631396589305390157506915312399058961554609342345998
b = 1005820216843804918712728918305396768000492821656453232969553225956348680715987662653812284211
F = GF(p)
E = EllipticCurve(F, [a, b])
n = E.order()
print("Order:", n)
print("Smooth factor:", factor(n))

# Load samples (parse manually since sage preparser breaks on big literal)
import re
raw = open("output.txt").read()
# Each tuple looks like: (a, b, (x : y : 1))
nums = re.findall(r"\d+", raw)
nums = [int(x) for x in nums]
# Each sample contributes: a, b, x, y, 1 → 5 numbers
res = []
for i in range(0, len(nums), 5):
    a_i, b_i, x, y, z = nums[i:i+5]
    assert z == 1
    res.append((a_i, b_i, (x, y)))
print("Got", len(res), "samples")

def to_pt(t):
    a_i, b_i, (x, y) = t
    return a_i, b_i, E(x, y)

a0, b0, R0 = to_pt(res[0])
a1, b1, R1 = to_pt(res[1])

# Recover P
m_p = (b1 * a0 - b0 * a1) % n
P = inverse_mod(m_p, n) * (b1 * R0 - b0 * R1)

# Recover Q
m_q = (a0 * b1 - a1 * b0) % n
Q = inverse_mod(m_q, n) * (a0 * R1 - a1 * R0)

# Verify
assert a0 * P + b0 * Q == R0
assert a1 * P + b1 * Q == R1
print("P, Q recovered and verified")

# Sanity: P.order() should divide n
print("P order divides n:", n % P.order() == 0)

# Solve ECDLP
FLAG = discrete_log(Q, P, ord=P.order(), operation='+')
print("FLAG int:", FLAG)
print("FLAG:", b"ECSC{" + long_to_bytes(int(FLAG)) + b"}")
