"""
Edwards Goes Degenerate.

The 'base point' (xbit=1, y=11) is *not* on the twisted Edwards curve, so
recover_x returns 0 and the actual base point becomes (0, 11). The Edwards
addition formula at points with x=0 collapses to:

    (0, y1) + (0, y2) = (0, y1 * y2 mod p)

So scalar multiplication degenerates into modular exponentiation in F_p*:

    [n] * (0, 11) = (0, 11^n mod p)

Both Alice's and Bob's public keys have x-bit = 0 in the output, and their
y-coordinates are 11^{n_A} and 11^{n_B} respectively. To break the protocol
we just solve a discrete log in F_p*. p-1 happens to be super-smooth (all
factors <~26 bits), so Pohlig-Hellman + BSGS finishes in milliseconds.
"""

from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sympy.ntheory.residue_ntheory import discrete_log, _discrete_log_pohlig_hellman
from sympy import factorint

p = 110791754886372871786646216601736686131457908663834453133932404548926481065303
order = 27697938721593217946661554150434171532902064063497989437820057596877054011573
d = 14053231445764110580607042223819107680391416143200240368020924470807783733946

alice_y = 109790246752332785586117900442206937983841168568097606235725839233151034058387
bob_y = 45290526009220141417047094490842138744068991614521518736097631206718264930032

iv = bytes.fromhex('31068e75b880bece9686243fa4dc67d0')
ct = bytes.fromhex(
    'e2ef82f2cde7d44e9f9810b34acc885891dad8118c1d9a07801639be0629b186dc8a192529703b2c947c20c4fe5ff2c8'
)

g = 11

# Discrete log: find n such that g^n = alice_y mod p.
# Provide factorization of p-1 to sympy for fast Pohlig-Hellman.
factors = factorint(p - 1)
print("p-1 factors:", factors)
n_a = _discrete_log_pohlig_hellman(p, alice_y, g, p - 1, factors)
print("n_a =", n_a)
assert pow(g, n_a, p) == alice_y, "discrete log failed"

# Shared secret y coord = bob_y^{n_a} mod p (matches gen_shared_secret).
shared_y = pow(bob_y, n_a, p)
print("shared y =", shared_y)

key = sha1(str(shared_y).encode('ascii')).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print("flag:", flag.decode())
