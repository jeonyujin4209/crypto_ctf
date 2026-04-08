import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

proof.all(False)

FLAG = b"crypto{?????????????????????????????????????????????????????????????}"

p = 2**127 - 1
F.<i> = GF(p^2, modulus=[1,0,1])
E = EllipticCurve(F, [1,0])
P, Q = E.gens()

a = randint(0, p) | 1
b = randint(0, p) | 1
c = randint(0, p) | 1
d = randint(0, p) | 1

R = a*P + b*Q
S = c*P + d*Q

def encrypt_flag(a, b, c, d):
    data_abcd = str(a) + str(b) + str(c) + str(d)
    key = SHA256.new(data=data_abcd.encode()).digest()[:128]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))

    return iv.hex(), ct.hex()

iv, ct = encrypt_flag(a, b, c, d)

print(f"{P = }")
print(f"{Q = }")
print(f"{R = }")
print(f"{S = }")
print()
print(f"{iv = }")
print(f"{ct = }")
