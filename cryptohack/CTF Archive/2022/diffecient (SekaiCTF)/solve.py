"""
Vulnerability: Bloom filter uses MurmurHash3_x86_32 (mmh3.hash), which has a
seed-independent differential collision (Aumasson-Bernstein style).

Body of mmh3:  T(h, k') = ROTL(h ^ k', 13) * 5 + c     (k' = process(k))
  where process(k) = ROTL(k * c1, 15) * c2  is bijective in k.

Two-block (8-byte) collision pair construction:
  Block 1: pick a1, b1 with process(a1) ^ process(b1) = 0x00040000 (bit 18)
           → state-XOR diff after ROTL13 = ROTL(0x00040000, 13) = 0x80000000
           → *5+c preserves a top-bit-only XOR diff exactly
             (5 * 2^31 mod 2^32 = 2^31, no carry into top bit either way)
  Block 2: pick a2, b2 with process(a2) ^ process(b2) = 0x80000000 (bit 31)
           → h_a ^ a2_p == h_b ^ b2_p → states EQUAL after block 2
  Append common suffix → mmh3(K1+suf, s) == mmh3(K2+suf, s) for ALL seeds.

Attack:
  1) Build collision pair (K1, K2) of 8 bytes, both \\n-free.
  2) sample = K1 + suffix (40B with [a-z][A-Z][\\d][\\W])
  3) admin  = K2 + suffix (different bytes → not in added_keys, but same hashes)
  4) check_admin returns True → server prints FLAG.
"""
import secrets
import sys
from pwn import remote, context

import mmh3

C1 = 0xCC9E2D51
C2 = 0x1B873593
MASK = 0xFFFFFFFF


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    assert g == 1
    return x % m


INV_C1 = modinv(C1, 1 << 32)
INV_C2 = modinv(C2, 1 << 32)


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def proc(k):
    k = (k * C1) & MASK
    k = rotl(k, 15)
    k = (k * C2) & MASK
    return k


def inv_proc(p):
    p = (p * INV_C2) & MASK
    p = rotr(p, 15)
    p = (p * INV_C1) & MASK
    return p


def find_collision_pair():
    while True:
        p1 = secrets.randbits(32)
        a1 = inv_proc(p1)
        b1 = inv_proc(p1 ^ 0x00040000)
        p3 = secrets.randbits(32)
        a2 = inv_proc(p3)
        b2 = inv_proc(p3 ^ 0x80000000)
        K1 = a1.to_bytes(4, 'little') + a2.to_bytes(4, 'little')
        K2 = b1.to_bytes(4, 'little') + b2.to_bytes(4, 'little')
        if K1 == K2:
            continue
        if b'\n' in K1 or b'\n' in K2:
            continue
        if all(mmh3.hash(K1, s) == mmh3.hash(K2, s) for s in range(47)):
            return K1, K2


def main():
    K1, K2 = find_collision_pair()
    suffix = b'abcDEFG1!23456789012345678901234'  # 32B, all classes, no \n
    sample = K1 + suffix
    admin = K2 + suffix
    assert sample != admin and len(admin) >= 32

    context.log_level = 'info'
    HOST, PORT = 'archive.cryptohack.org', 29201
    io = remote(HOST, PORT)

    io.recvuntil(b'Enter API option:\n')
    io.sendline(b'2')
    io.recvuntil(b'Enter key in hex\n')
    io.sendline(sample.hex().encode())
    print(io.recvline().decode().strip())  # "key added successfully to DB"

    io.recvuntil(b'Enter API option:\n')
    io.sendline(b'3')
    io.recvuntil(b'Enter key in hex\n')
    io.sendline(admin.hex().encode())
    line = io.recvline().decode().strip()
    print('SERVER:', line)
    # If admin succeeded, the next line is the flag (no error msg).
    try:
        more = io.recv(timeout=2).decode(errors='replace')
        if more.strip():
            print('FLAG:', more.strip())
    except Exception:
        pass

    io.close()


if __name__ == '__main__':
    main()
