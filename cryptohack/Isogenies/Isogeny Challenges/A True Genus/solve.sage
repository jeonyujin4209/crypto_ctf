"""
A True Genus - CSIDH genus theory / DDH-CGA distinguisher

Key insight: For CSIDH DH triple (EA, EB, EC):
  δ(base, EA) == δ(EB, EC)   ←→   EC is the shared secret (bit=1)

compute_supersingular_delta(E0, E_test) computes the genus character χ:
  1. Find r = root of x^3 + a4(E0)*x + a6(E0) in GF(p^2)
  2. Find riso = root of x^3 + a4(E_test)*x + a6(E_test) in GF(p^2)
  3. char = ((a4(E_test)+3*riso^2) / (a4(E0)+3*r^2))^((p-1)/4) → ±1

This is NOT related to the j-invariant or simple Legendre symbols.
It uses the derivative of the Weierstrass polynomial at a 2-torsion point.
No CSIDH class group DLP needed - just character evaluation.
"""
import json
proof.all(False)

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ls = list(primes(3, 112)) + [139]
p = 2 * prod(ls) - 1
Fp2 = GF(p**2, names="w", modulus=[3, 0, 1])
w = Fp2.gen()
base = EllipticCurve(Fp2, [0, 1])


def compute_supersingular_delta(E_0, E_test):
    """Genus character χ: given base curve E_0 and test curve E_test, returns ±1.

    For a DH triple (EA, EB, EC=shared), χ(base→EA) == χ(EB→EC).
    For a random triple, χ(base→EA) and χ(EB→EC) are independent ±1.
    """
    Fx = PolynomialRing(E_0.base_field(), 'x')
    x = Fx.gen()
    a = E_0.a4()
    r    = (x^3 + a*x + E_0.a6()).roots()[0][0]
    riso = (x^3 + E_test.a4()*x + E_test.a6()).roots()[0][0]
    char = ((E_test.a4() + 3*riso^2) / (a + 3*r^2))^((p - 1) // 4)
    return 1 if char == 1 else -1


with open("/home/sage/output.txt") as f:
    data = json.load(f)

iv = bytes.fromhex(data['iv'])
ct = bytes.fromhex(data['ct'])
challenge_data = data['challenge_data']

print(f"[*] Processing {len(challenge_data)} bit challenges ...")
key_bits = ""
for i, entry in enumerate(challenge_data):
    def load_curve(d):
        a4 = Fp2(d['a4'][0] + d['a4'][1]*w) if len(d['a4']) > 1 else Fp2(d['a4'][0])
        a6 = Fp2(d['a6'][0] + d['a6'][1]*w) if len(d['a6']) > 1 else Fp2(d['a6'][0])
        return EllipticCurve(Fp2, [a4, a6])

    EA = load_curve(entry['EA'])
    EB = load_curve(entry['EB'])
    EC = load_curve(entry['EC'])

    d_base_A = compute_supersingular_delta(base, EA)
    d_B_C    = compute_supersingular_delta(EB, EC)

    key_bits += "1" if d_base_A == d_B_C else "0"
    if (i+1) % 8 == 0:
        print(f"  [{i+1}/{len(challenge_data)}] bits so far: {key_bits[-8:]}")

print(f"[+] key_bits = {key_bits}")
secret = int(key_bits[::-1], 2)
print(f"[+] SECRET = {secret}")

key = SHA256.new(int.to_bytes(int(secret), 8, 'big')).digest()[:32]
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(f"[+] FLAG: {flag.decode()}")
