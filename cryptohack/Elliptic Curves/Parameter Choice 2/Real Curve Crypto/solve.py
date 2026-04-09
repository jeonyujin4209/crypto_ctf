"""
Real Curve Crypto (200pts) — CryptoHack Elliptic Curves / Parameter Choice 2

The "elliptic curve" y^2 = x^3 - x is computed over the REALS (mpmath, 200 dps),
not over a finite field. So ECDLP is replaced by real elliptic logarithm.

For E: y^2 = f(x) = x^3 - x with 3 real roots {-1, 0, 1}, the unbounded component
(x >= 1) is topologically a circle (after compactifying at infinity = identity).
The elliptic log map
    u(P) = ∫_{x_P}^∞ dt / sqrt(t^3 - t)
is a group homomorphism from the unbounded branch to R / (ω Z), where
    ω = 2 · ∫_1^∞ dt / sqrt(t^3 - t)
is the real period.

So scalar multiplication satisfies:
    u(N·G) ≡ N · u(G)   (mod ω)

We have G and P = N·G with high-precision coordinates and need to recover N.
That gives one linear relation:
    N · u_G − k · ω − u_P = 0      (k ∈ Z, k ~ N · u_G / ω)
which is exactly the kind of integer relation that mpmath.pslq is designed for.

Then N is the AES key (16 bytes) used to encrypt the flag (CBC + PKCS7 pad).
"""

from mpmath import mp, mpf, quad, sqrt, pslq, inf, gamma, pi
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
import json
import os

mp.dps = 500  # need high precision for PSLQ + 128-bit coefficients

DIR = os.path.dirname(__file__)
with open(os.path.join(DIR, "output.txt")) as f:
    data = json.load(f)

gx = mpf(data["gx"])
gy = mpf(data["gy"])
px = mpf(data["px"])
py = mpf(data["py"])
ciphertext = bytes.fromhex(data["ciphertext"])
iv = bytes.fromhex(data["iv"])

print(f"gx = {gx}")
print(f"px = {px}")
assert gy > 0 and py > 0, "expected positive y on unbounded branch"

# Elliptic log on the unbounded branch (x > 1, y > 0).
# Use substitution t = 1 + 1/s^2  →  ds = -2/s^3 · ... to make the integral
# numerically nice, but for x clearly > 1 (no singularity) plain quad is fine.
def ell_log(x):
    # No endpoint singularities (x > 1, well-behaved at infinity ~ 1/t^(3/2)).
    return quad(lambda t: 1 / sqrt(t**3 - t), [x, inf])

# Real period ω of the unbounded branch.
# Substitute u = 1/sqrt(t)  ⇒  ω = 2·∫_1^∞ dt/sqrt(t^3-t) = 4·∫_0^1 du/sqrt(1-u^4)
#         = Γ(1/4)·√π / Γ(3/4)
# (Closed form via Beta function — exact to mpmath precision.)
omega = gamma(mpf(1) / 4) * sqrt(pi) / gamma(mpf(3) / 4)

print("\nComputing elliptic logarithms...")
uG = ell_log(gx)
uP = ell_log(px)

print(f"u_G   ~ {mp.nstr(uG,  30)}")
print(f"u_P   ~ {mp.nstr(uP,  30)}")
print(f"omega ~ {mp.nstr(omega, 30)}")
print(f"u_G/omega ~ {mp.nstr(uG/omega, 30)}")
print(f"u_P/omega ~ {mp.nstr(uP/omega, 30)}")

# Sanity check: ω should equal 2·∫_1^∞ dt/sqrt(t^3-t) (numeric vs closed form).
omega_numeric = 2 * quad(lambda t: 1 / sqrt(t**3 - t), [1, inf])
print(f"\nclosed-form ω vs numeric ω: diff = {mp.nstr(omega - omega_numeric, 5)}")

# Find integers (N, k, c) with c = ±1 such that  N · u_G + k · ω + c · u_P = 0.
# Equivalently:  N · u_G ≡ u_P  (mod ω).
#
# The original output was computed at mp.dps = 200, with O(log2 N) ~ 128 doublings
# accumulating rounding loss. Effective precision of px is roughly 200 − 50 = 150
# digits, so the discovered relation can only be expected to hold to ~150 digits.
print("\nRunning PSLQ to find integer relation...")
relation = None
for tol_exp in (150, 130, 110, 90, 70, 50):
    print(f"  trying tol = 10^-{tol_exp} ...", end=" ", flush=True)
    relation = pslq(
        [uG, omega, uP],
        tol=mp.mpf(10) ** -tol_exp,
        maxcoeff=10**45,
        maxsteps=10000,
    )
    print(relation)
    if relation is not None:
        break

assert relation is not None, "PSLQ did not converge"

a, b, c = relation
# a · uG + b · ω + c · uP = 0  →  N · uG ≡ −(c/a)... easier: pick the sign so c = ±1
# Standard form we want: N · uG − k · ω − uP = 0  →  a = N, b = −k, c = −1
if c == 1:
    a, b, c = -a, -b, -c
assert c == -1, f"unexpected coefficient c = {c}; relation = {relation}"
N = a
k = -b
print(f"\nRecovered N = {N}")
print(f"           k = {k}")
print(f"  bit length = {N.bit_length()}")
assert N.bit_length() <= 128, "N should fit in 128 bits (16 bytes)"

# Decrypt the flag
key = long_to_bytes(N, 16)
print(f"  key (hex) = {key.hex()}")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
print(f"\nraw plaintext: {plaintext}")
try:
    flag = unpad(plaintext, 16)
    print(f"\nFLAG: {flag.decode()}")
except Exception as e:
    print(f"unpad failed: {e}")
    print(f"plaintext bytes: {plaintext}")
