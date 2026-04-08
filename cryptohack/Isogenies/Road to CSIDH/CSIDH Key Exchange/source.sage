import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

FLAG = b"crypto{??????????????????????????????????????}"

# CSIDH-512 prime
ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])

a_priv = [-1, -2, -3, -3, -2, -3, -3, 0, 2, -1, 2, -1, -2, -3, 1, 2, 1, 2, 0, 0, 1, -1, 0, 2, -1, 0, 0, 0, 1, -1, -3, 1, -1, -3, -3, 2, 2, 1, -1, -1, 1, 0, 1, 1, 1, -2, 2, 2, -2, -2, 0, 0, 2, 0, -1, -3, -2, -2, 0, -1, -3, -1, -2, -3, -2, 2, 1, 1, -2, 0, 1, -1, -3, 2]
b_priv = [-1, -1, 0, 1, 2, 0, 2, -1, -3, 1, 0, -2, -2, 2, -1, -2, -3, -3, -3, 2, 2, 2, -2, -1, 1, -2, 0, -3, -1, 1, -1, -1, -3, -1, -2, 1, -1, -2, -3, 1, 0, -1, 1, 2, 2, 0, 0, -1, -2, -2, 1, -1, 1, 1, 1, 1, 0, 0, 0, -3, -2, -1, 2, 0, -3, -2, 1, 1, -2, -1, -1, 2, 0, 1]

# TODO: Compute:
# - Alice's Public Key
# - Bob's Public Key
# - Both their shared secrets and ensure they match!
# - Remember: the shared secret is the Montgomery coefficient A
shared_secret = None # TODO

def encrypt_flag(shared_secret):
    key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))

    return iv.hex(), ct.hex()

print(encrypt_flag(shared_secret))
# ('daf6cd181775664b099609789fb564c9', '3dd92e255c8e677f4a92226d09f56e2b2f567052ffd4f6f60200018454a83affc2e694c2bf2ad27da38f7f49b6e89928')
