from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha1
from sympy.ntheory import discrete_log
from collections import namedtuple

Point = namedtuple("Point", "x y")

# Curve parameters
p = 173754216895752892448109692432341061254596347285717132408796456167143559
D = 529  # = 23^2
sqrt_D = 23

G = Point(x=29394812077144852405795385333766317269085018265469771684226884125940148,
          y=94108086667844986046802106544375316173742538919949485639896613738390948)

A = Point(x=155781055760279718382374741001148850818103179141959728567110540865590463,
          y=73794785561346677848810778233901832813072697504335306937799336126503714)

B = Point(x=171226959585314864221294077932510094779925634276949970785138593200069419,
          y=54353971839516652938533335476115503436865545966356461292708042305317630)

iv = bytes.fromhex('64bc75c8b38017e1397c46f85d4e332b')
encrypted_flag = bytes.fromhex('13e4d200708b786d8f7c3bd2dc5de0201f0d7879192e6603d7c5d6b963e1df2943e3ff75f7fda9c30a92171bbbc5acbf')

# Since D = 23^2, sqrt(D) = 23 exists in Z_p.
# The "curve" x^2 - D*y^2 = 1 factors as (x + 23y)(x - 23y) = 1.
# Map point P -> z = (P.x + 23*P.y) mod p
# Then point_addition maps to multiplication, scalar_multiplication maps to exponentiation.

g_val = (G.x + sqrt_D * G.y) % p
a_val = (A.x + sqrt_D * A.y) % p
b_val = (B.x + sqrt_D * B.y) % p

print(f"g_val = {g_val}")
print(f"a_val = {a_val}")
print(f"b_val = {b_val}")

# Solve discrete log: g_val^n_a = a_val mod p
# Group order is p-1
print("Computing discrete log...")
n_a = discrete_log(p, a_val, g_val)
print(f"n_a = {n_a}")

# Compute shared secret = scalar_multiplication(B, n_a).x
# In the mapped domain: b_val^n_a mod p gives us (shared.x + 23*shared.y)
# We also need (shared.x - 23*shared.y) = b_minus^n_a where b_minus = (B.x - 23*B.y) mod p
shared_plus = pow(b_val, n_a, p)
b_minus = (B.x - sqrt_D * B.y) % p
shared_minus = pow(b_minus, n_a, p)

# shared.x = (shared_plus + shared_minus) / 2 mod p
inv2 = pow(2, p - 2, p)
shared_x = (shared_plus + shared_minus) * inv2 % p
print(f"shared_secret (x) = {shared_x}")

# Derive AES key and decrypt
key = sha1(str(shared_x).encode('ascii')).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(encrypted_flag), 16)
print(f"Flag: {flag.decode()}")
