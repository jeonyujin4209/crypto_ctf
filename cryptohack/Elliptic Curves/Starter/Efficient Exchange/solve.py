from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

p = 9739
a = 497
b = 1768

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(n, P):
    R = None
    Q = P
    while n > 0:
        if n & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        n >>= 1
    return R

# Recover y from x for the curve y^2 = x^3 + 497x + 1768 mod 9739
# Since p ≡ 3 mod 4, sqrt(a) = a^((p+1)/4) mod p
x_QA = 4726
y_sq = (pow(x_QA, 3, p) + a * x_QA + b) % p
y = pow(y_sq, (p + 1) // 4, p)
assert (y * y) % p == y_sq

# Both y values give the same x-coordinate for the shared secret
QA = (x_QA, y)
nB = 6534

S = scalar_mult(nB, QA)

# Decrypt
iv = 'cd9da9f1c60925922377ea952afc212c'
ciphertext = 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'

sha1 = hashlib.sha1()
sha1.update(str(S[0]).encode('ascii'))
key = sha1.digest()[:16]

ct = bytes.fromhex(ciphertext)
iv_bytes = bytes.fromhex(iv)
cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
plaintext = unpad(cipher.decrypt(ct), 16)
print(plaintext.decode('ascii'))
