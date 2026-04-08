#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

e = 0x10001

# n will be 8 * (100 + 100) = 1600 bits strong (I think?) which is pretty good
p = getPrime(100)
q = getPrime(100)
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

n = p * q

FLAG = b"crypto{???????????????}"
pt = bytes_to_long(FLAG)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == FLAG
