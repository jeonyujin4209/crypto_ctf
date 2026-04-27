"""
Vulnerability: Schnorr-Probabilistic-Signature Scheme (PSS-style) where the
challenger gives 10000 sigs of which only ONE is real (the rest are random).
We can identify the real one by verifying — with c = H(r), R = z*G + c*Y
(since Y = -x*G, so z*G + c*Y = (omega + c*x)*G - c*x*G = omega*G), then
m1 = r XOR R.x_bytes must satisfy F1(F2(a) XOR b) == a where m1 = a||b,
|a|=k1=320 bits, |b|=k2=128 bits. Random sigs fail with prob ~2^-320.

Once real sig found, m = F2(a) XOR b is the bcrypt seed; derive AES key,
decrypt CT in AES-CTR.
"""
import hashlib, ast, operator, re, time, sys

p_field = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p_field)
a_param = K(0x01)
d_param = K(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756)
A_w = K(-1/48) * (a_param^2 + 14*a_param*d_param + d_param^2)
B_w = K(1/864) * (a_param + d_param) * (-a_param^2 + 34*a_param*d_param - d_param^2)
E = EllipticCurve(K, (A_w, B_w))

def to_weierstrass(x, y):
    return ((5*a_param + a_param*y - 5*d_param*y - d_param)/(12 - 12*y),
            (a_param + a_param*y - d_param*y - d_param)/(4*x - 4*x*y))

Gx_te = K(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555)
Gy_te = K(0xae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed)
Gw = E(*to_weierstrass(Gx_te, Gy_te))
order_total = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3 * 0x04
E.set_order(order_total)
n = order_total // 4   # the prime order subgroup we sign in

q_field = 2**448 - 2**224 - 1
k_bits = 8*((len(bin(n)) - 2 + 7) // 8)   # 448
k2 = 128
k1 = 8*((7 + len(bin(q_field)) - 2)//8) - k2  # 320
RBYTES = (k1 + k2) // 8   # 56
K1B = k1 // 8             # 40
K2B = k2 // 8             # 16

def Hash(x, nin, n_, div):
    nin //= 8; n_ //= 8
    assert len(x) == nin
    r = b""
    i = 0
    while len(r) < n_:
        r += hashlib.sha256(x + b"||" + div + int(i).to_bytes(8, "big")).digest()
        i += 1
    return r[:n_]

F1 = lambda x: Hash(x, k2, k1, b"1")
F2 = lambda x: Hash(x, k1, k2, b"2")
H_fn = lambda x: Hash(x, k1+k2, k_bits, b"H")

def xor(a, b):
    return bytes(map(operator.xor, a, b))

with open("output.txt") as f:
    lines = f.read().splitlines()

m = re.match(r"Y = \((\d+), (\d+)\)", lines[0])
Y_te_x = K(Integer(m.group(1)))
Y_te_y = K(Integer(m.group(2)))
Yw = E(*to_weierstrass(Y_te_x, Y_te_y))
print(f"Y on curve: {Yw in E}")

ct_hex = lines[1].split(" = ")[1].strip()
ct = bytes.fromhex(ct_hex)
print(f"ct len: {len(ct)}")

print("parsing sigs...")
sigs = ast.literal_eval(lines[2])
print(f"got {len(sigs)} sigs")

t0 = time.time()
found = None
for idx, (r_hex, z) in enumerate(sigs):
    if idx % 500 == 0:
        print(f"  [{idx}/{len(sigs)}] {time.time()-t0:.1f}s")
    r = bytes.fromhex(r_hex)
    c = int.from_bytes(H_fn(r), "big")
    R = Integer(z) * Gw + Integer(c) * Yw
    if R == 0:
        continue
    Rx = Integer(R.xy()[0])
    rx_bytes = int(Rx).to_bytes(RBYTES, "big")
    m1 = xor(rx_bytes, r)
    a_part = m1[:K1B]
    b_part = m1[K1B:]
    msg = xor(F2(a_part), b_part)
    if F1(msg) == a_part:
        print(f"FOUND at idx={idx}: msg={msg.hex()}")
        found = msg
        break

if found is None:
    sys.exit("no real sig identified")

print(f"k = {found.hex()}")
import bcrypt
from Crypto.Cipher import AES
key = bcrypt.kdf(found, b"ICC_CHALLENGE", 16, 31337)
cipher = AES.new(key, AES.MODE_CTR, nonce=b"")
flag = cipher.decrypt(ct)
print(f"FLAG: {flag}")
