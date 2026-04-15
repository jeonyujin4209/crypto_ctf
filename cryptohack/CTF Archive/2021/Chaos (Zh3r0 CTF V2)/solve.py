import time
from z3 import *

# ===== Original hash function (for verification) =====
def ROTL(value, bits, size=32):
    return ((value % (1 << (size - bits))) << bits) | (value >> (size - bits))

def ROTR(value, bits, size=32):
    return ((value % (1 << bits)) << (size - bits)) | (value >> bits)

def pad(pt):
    pt += b'\x80'
    L = len(pt)
    to_pad = 60 - (L % 64) if L % 64 <= 60 else 124 - (L % 64)
    padding = bytearray(to_pad) + int.to_bytes(L - 1, 4, 'big')
    return pt + padding

def hash_func(text: bytes):
    text = pad(text)
    text = [int.from_bytes(text[i:i+4], 'big') for i in range(0, len(text), 4)]
    M = 0xffff
    x, y, z, u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
    A, B, C, D = 0x401ab257, 0xb7cd34e1, 0x76b3a27c, 0xf13c3adf
    RV1, RV2, RV3, RV4 = 0xe12f23cd, 0xc5ab6789, 0xf1234567, 0x9a8bc7ef
    for i in range(0, len(text), 4):
        X, Y, Z, U = text[i] ^ x, text[i+1] ^ y, text[i+2] ^ z, text[i+3] ^ u
        RV1 ^= (x := (X & 0xffff) * (M - (Y >> 16)) ^ ROTL(Z, 1) ^ ROTR(U, 1) ^ A)
        RV2 ^= (y := (Y & 0xffff) * (M - (Z >> 16)) ^ ROTL(U, 2) ^ ROTR(X, 2) ^ B)
        RV3 ^= (z := (Z & 0xffff) * (M - (U >> 16)) ^ ROTL(X, 3) ^ ROTR(Y, 3) ^ C)
        RV4 ^= (u := (U & 0xffff) * (M - (X >> 16)) ^ ROTL(Y, 4) ^ ROTR(Z, 4) ^ D)
    for i in range(4):
        RV1 ^= (x := (X & 0xffff) * (M - (Y >> 16)) ^ ROTL(Z, 1) ^ ROTR(U, 1) ^ A)
        RV2 ^= (y := (Y & 0xffff) * (M - (Z >> 16)) ^ ROTL(U, 2) ^ ROTR(X, 2) ^ B)
        RV3 ^= (z := (Z & 0xffff) * (M - (U >> 16)) ^ ROTL(X, 3) ^ ROTR(Y, 3) ^ C)
        RV4 ^= (u := (U & 0xffff) * (M - (X >> 16)) ^ ROTL(Y, 4) ^ ROTR(Z, 4) ^ D)
    return int.to_bytes((RV1 << 96) | (RV2 << 64) | (RV3 << 32) | RV4, 16, 'big')


# ===== Z3 collision finder =====
# Key insight: finalization loop XORs same value 4 times = no-op.
# For same-length messages, collision in first round => full hash collision.
# Fix Z, U to concrete values; use bit-blast + SAT for speed.

print("Setting up Z3 solver (bit-blast + SAT)...")

Z_concrete = 0xdeadbeef
U_concrete = 0xcafebabe

Xv = BitVec('X', 32)
Yv = BitVec('Y', 32)
Xp = BitVec('Xp', 32)
Yp = BitVec('Yp', 32)

Mz = BitVecVal(0xffff, 32)
Zz = BitVecVal(Z_concrete, 32)
Uz = BitVecVal(U_concrete, 32)
Az = BitVecVal(0x401ab257, 32)
Bz = BitVecVal(0xb7cd34e1, 32)
Cz = BitVecVal(0x76b3a27c, 32)
Dz = BitVecVal(0xf13c3adf, 32)

def z3_round(X, Y, Z, U):
    x = (X & Mz) * (Mz - LShR(Y, 16)) ^ RotateLeft(Z, 1) ^ RotateRight(U, 1) ^ Az
    y = (Y & Mz) * (Mz - LShR(Z, 16)) ^ RotateLeft(U, 2) ^ RotateRight(X, 2) ^ Bz
    z = (Z & Mz) * (Mz - LShR(U, 16)) ^ RotateLeft(X, 3) ^ RotateRight(Y, 3) ^ Cz
    u = (U & Mz) * (Mz - LShR(X, 16)) ^ RotateLeft(Y, 4) ^ RotateRight(Z, 4) ^ Dz
    return x, y, z, u

x1, y1, z1, u1 = z3_round(Xv, Yv, Zz, Uz)
x2, y2, z2, u2 = z3_round(Xp, Yp, Zz, Uz)

# Use bit-blast tactic: converts bitvector problem to SAT
tactic = Then('simplify', 'bit-blast', 'sat')
s = tactic.solver()
s.add(x1 == x2)
s.add(y1 == y2)
s.add(z1 == z2)
s.add(u1 == u2)
s.add(Or(Xv != Xp, Yv != Yp))

print("Solving...")
start = time.time()
result = s.check()
elapsed = time.time() - start
print(f"Result: {result} ({elapsed:.1f}s)")

if result == sat:
    model = s.model()
    X_val = model[Xv].as_long()
    Y_val = model[Yv].as_long()
    Xp_val = model[Xp].as_long()
    Yp_val = model[Yp].as_long()

    # Convert to message words (XOR with initial state)
    x0, y0, z0, u0 = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
    t  = [X_val ^ x0, Y_val ^ y0, Z_concrete ^ z0, U_concrete ^ u0]
    tp = [Xp_val ^ x0, Yp_val ^ y0, Z_concrete ^ z0, U_concrete ^ u0]

    m1 = b''.join(w.to_bytes(4, 'big') for w in t)
    m2 = b''.join(w.to_bytes(4, 'big') for w in tp)

    print(f"\nm1 = {m1.hex()}")
    print(f"m2 = {m2.hex()}")
    print(f"m1 != m2: {m1 != m2}")

    h1 = hash_func(m1)
    h2 = hash_func(m2)
    print(f"\nhash(m1) = {h1.hex()}")
    print(f"hash(m2) = {h2.hex()}")
    print(f"Collision found: {h1 == h2}")
else:
    print("No solution found")
