"""
No Difference (Hash Functions / Collisions) — POC solver

Server (13395.py) accepts {"a": hex, "b": hex}. Both must be multiples of 4
bytes, different, and satisfy hash(a) == hash(b). Returns the flag on collision.

The custom hash has the structure:
    state = [16,32,48,80,80,96,112,128]
    for each 4-byte block:
        state[4..8] ^= block
        state = substitute(permute(state))        # permute = bit transpose
    <16 rounds of permute+substitute>
    <truncated output: 2 x state[4..8]>

Key weakness: the S-box satisfies  SBOX[x] = SBOX[x XOR 0xdf]  (128 pairs
verified). So any pre-substitute byte difference in {0x00, 0xdf} collapses
after the S-box.

Single-block collision is impossible: with pre-permute diff living only in
bytes 4..7 (from the block XOR), after the bit-transpose every post-permute
byte has low nibble 0. `0xdf` has low nibble `f`, so no byte can be 0xdf, only
0x00 — forcing the full diff to 0.

Two-block collision works with a nicer differential:

  Round 1. Pick A1, B1 that differ *only in the high nibbles* of bytes 0..3,
           i.e. the 4-byte XOR (ΔA) has zero low nibbles. Then pre-permute
           diff = [0,0,0,0, ΔA0, ΔA1, ΔA2, ΔA3]. After the bit transpose,
           since ΔA has zero low nibbles, post-permute bytes 0..3 are all 0.
           Post-permute bytes 4..7 can be nonzero. So after substitute the
           round-1 state difference D1 has   D1[0..4] == 0   and   D1[4..8]
           arbitrary.

  Round 2. The only difference between TA_1 and TB_1 is in bytes 4..7. We
           choose the second block so that A2 XOR B2 = D1[4..8]. After
           XOR-ing into state[4..8], both messages now have *identical*
           state. Permute + substitute leaves them equal, and all subsequent
           (deterministic) processing produces the same hash output.

Messages constructed by this script:
  a = 00 00 00 00 00 00 00 00
  b = 10 00 00 00 85 00 00 00
"""

import json
import socket
import sys

# S-box lifted from 13395.py
SBOX = [
    0xf0, 0xf3, 0xf1, 0x69, 0x45, 0xff, 0x2b, 0x4f, 0x63, 0xe1, 0xf3, 0x71, 0x44, 0x1b, 0x35, 0xc8,
    0xbe, 0xc0, 0x1a, 0x89, 0xec, 0x3e, 0x1d, 0x3a, 0xe3, 0xbe, 0xd3, 0xcf, 0x20, 0x4e, 0x56, 0x22,
    0xe4, 0x43, 0x9a, 0x6f, 0x43, 0xa9, 0x87, 0x37, 0xec, 0x2, 0x3b, 0x8a, 0x7a, 0x13, 0x7e, 0x79,
    0xcc, 0x92, 0xd7, 0xd1, 0xff, 0x5e, 0xe2, 0xb1, 0xc9, 0xd3, 0xda, 0x40, 0xfb, 0x80, 0xe6, 0x30,
    0x79, 0x1a, 0x28, 0x13, 0x1f, 0x2c, 0x73, 0xb9, 0x71, 0x9e, 0xa6, 0xd5, 0x30, 0x84, 0x9d, 0xa1,
    0x9b, 0x6d, 0xf9, 0x8a, 0x3d, 0xe9, 0x47, 0x15, 0x50, 0xb, 0xe2, 0x3d, 0x3f, 0x1, 0x59, 0x9b,
    0x85, 0xe4, 0xe5, 0x90, 0xe2, 0x2d, 0x80, 0x5e, 0x6b, 0x77, 0xa1, 0x10, 0x99, 0x72, 0x7f, 0x86,
    0x1f, 0x25, 0xa3, 0xea, 0x57, 0x5f, 0xc4, 0xc6, 0x7d, 0x7, 0x15, 0x90, 0xcb, 0x8c, 0xec, 0x11,
    0x9b, 0x59, 0x1, 0x3f, 0x3d, 0xe2, 0xb, 0x50, 0x15, 0x47, 0xe9, 0x3d, 0x8a, 0xf9, 0x6d, 0x9b,
    0xa1, 0x9d, 0x84, 0x30, 0xd5, 0xa6, 0x9e, 0x71, 0xb9, 0x73, 0x2c, 0x1f, 0x13, 0x28, 0x1a, 0x79,
    0x11, 0xec, 0x8c, 0xcb, 0x90, 0x15, 0x7, 0x7d, 0xc6, 0xc4, 0x5f, 0x57, 0xea, 0xa3, 0x25, 0x1f,
    0x86, 0x7f, 0x72, 0x99, 0x10, 0xa1, 0x77, 0x6b, 0x5e, 0x80, 0x2d, 0xe2, 0x90, 0xe5, 0xe4, 0x85,
    0x22, 0x56, 0x4e, 0x20, 0xcf, 0xd3, 0xbe, 0xe3, 0x3a, 0x1d, 0x3e, 0xec, 0x89, 0x1a, 0xc0, 0xbe,
    0xc8, 0x35, 0x1b, 0x44, 0x71, 0xf3, 0xe1, 0x63, 0x4f, 0x2b, 0xff, 0x45, 0x69, 0xf1, 0xf3, 0xf0,
    0x30, 0xe6, 0x80, 0xfb, 0x40, 0xda, 0xd3, 0xc9, 0xb1, 0xe2, 0x5e, 0xff, 0xd1, 0xd7, 0x92, 0xcc,
    0x79, 0x7e, 0x13, 0x7a, 0x8a, 0x3b, 0x2, 0xec, 0x37, 0x87, 0xa9, 0x43, 0x6f, 0x9a, 0x43, 0xe4,
]

HOST = "socket.cryptohack.org"
PORT = 13395
TIMEOUT = 15


def permute(block):
    result = [0] * 8
    for i in range(8):
        x = block[i]
        for j in range(8):
            result[j] |= (x & 1) << i
            x >>= 1
    return result


def substitute(block):
    return [SBOX[x] for x in block]


def hash_fn(data: bytes) -> bytes:
    assert len(data) % 4 == 0
    state = [16, 32, 48, 80, 80, 96, 112, 128]
    for i in range(0, len(data), 4):
        block = data[i:i + 4]
        state[4] ^= block[0]
        state[5] ^= block[1]
        state[6] ^= block[2]
        state[7] ^= block[3]
        state = permute(state)
        state = substitute(state)
    for _ in range(16):
        state = permute(state)
        state = substitute(state)
    output = []
    for _ in range(2):
        output += state[4:]
        state = permute(state)
        state = substitute(state)
    return bytes(output)


def _round(state, block):
    s = list(state)
    s[4] ^= block[0]
    s[5] ^= block[1]
    s[6] ^= block[2]
    s[7] ^= block[3]
    s = permute(s)
    s = substitute(s)
    return s


def build_collision():
    # Verify SBOX property
    for x in range(256):
        assert SBOX[x] == SBOX[x ^ 0xdf], "SBOX symmetry broken"

    # Pick A1, B1 differing only in high nibbles (low nibbles stay 0 → diff has
    # low nibbles 0 → post-permute diff has zero low half)
    A1 = bytes([0x00, 0x00, 0x00, 0x00])
    B1 = bytes([0x10, 0x00, 0x00, 0x00])  # ΔA = [0x10,0,0,0], low nibbles 0

    S0 = [16, 32, 48, 80, 80, 96, 112, 128]
    TA_1 = _round(S0, A1)
    TB_1 = _round(S0, B1)
    D1 = [a ^ b for a, b in zip(TA_1, TB_1)]
    assert D1[:4] == [0, 0, 0, 0], f"bad differential: D1[:4] = {D1[:4]}"

    # Cancel D1's last 4 bytes in round 2 via block XOR
    A2 = bytes([0x00, 0x00, 0x00, 0x00])
    B2 = bytes([D1[4], D1[5], D1[6], D1[7]])

    a = A1 + A2
    b = B1 + B2
    assert a != b
    assert hash_fn(a) == hash_fn(b), "local collision verification FAILED"
    return a, b


def open_session(host, port):
    sock = socket.create_connection((host, port))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # greeting
    return sock, f


def submit(a: bytes, b: bytes, host: str, port: int) -> dict:
    sock, f = open_session(host, port)
    try:
        payload = json.dumps({"a": a.hex(), "b": b.hex()}).encode() + b"\n"
        f.write(payload)
        line = f.readline()
        return json.loads(line.decode())
    finally:
        sock.close()


def main() -> None:
    a, b = build_collision()
    print(f"[+] local collision confirmed")
    print(f"    a    = {a.hex()}")
    print(f"    b    = {b.hex()}")
    print(f"    hash = {hash_fn(a).hex()}")

    host, port = HOST, PORT
    if len(sys.argv) > 1 and sys.argv[1] == "--local":
        host, port = "127.0.0.1", 13395
        print(f"[*] using local server {host}:{port}")

    resp = submit(a, b, host, port)
    print(f"[+] server: {resp}")


if __name__ == "__main__":
    main()
