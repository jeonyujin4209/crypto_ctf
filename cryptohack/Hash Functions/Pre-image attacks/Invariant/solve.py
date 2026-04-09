"""
Invariant (Hash Functions / Pre-image attacks) — POC solver

Server (13393.py) defines a custom block cipher MyCipher (4-bit S-box, 31 rounds,
operating on 16 nibbles = 64 bits) and a Matyas-Meyer-Oseas-style hash:

    h_0 = 0
    h_{i+1} = encrypt(h_i XOR B_i) XOR B_i      (cipher key = sha512(content))

Server returns the FLAG iff we send `data` whose MyHash digest is 0^8.

Invariant — the {6, 7} subset
-----------------------------
Let `INV = {6, 7}` (4-bit values whose top three bits are 011). Claim: if every
nibble of the cipher *input* lies in INV, then so does every nibble of the
cipher *output*, regardless of the key. Proof, step by step over one round:

  AddRoundKey:    Each subkey bit only XORs the LSB of one nibble.
                  6 = 0110, 7 = 0111 differ only in their LSB, so toggling
                  the LSB keeps each nibble in INV.

  SubBytes:       SB = [13,14,0,1,5,10,7,6,11,3,9,12,15,8,2,4]
                  SB[6] = 7, SB[7] = 6 — SB is a 2-cycle on INV, so SB(INV) = INV.

  ShiftRows:      Just a permutation of nibble positions. INV-membership unchanged.

  MixColumns:     X[c] = XOR of 4 nibbles in column c.
                  All 4 nibbles in {6,7} ⇒ X[c] ∈ {0, 1}
                  (any number of 6's XORs to 0; each 7 contributes a 1).
                  Then new_S[c, r] = X[c] XOR old_S[4c + r] ∈ {0,1} XOR {6,7} = {6,7}.

  Final AddRK:    LSB toggle, again preserves INV.

So if `block ∈ INV^16`, then encrypt(block) ∈ INV^16 too. And the hash output
of a single-block input is `encrypt(block) XOR block`, which has nibbles in
{0, 1} = `{6 XOR 6, 6 XOR 7, 7 XOR 6, 7 XOR 7}` — i.e. all top-three-bits zero.

Strategy
--------
A 1-block brute-force in INV^16 fails: empirically the cipher restricted to
INV^16 has zero fixed points (there is a 1-bit linear bias forcing one specific
output bit to differ from the input bit for *most* keys, so block == enc(block)
never happens for length-8 inputs).

Use 2-block content instead. With B1, B2 ∈ INV^16:

      h_1 = enc_K(B1) XOR B1                 ∈ {0,1}^16
      h_2 = enc_K(h_1 XOR B2) XOR B2         ∈ {0,1}^16

For h_2 to be 0 we need enc_K(h_1 XOR B2) == B2. Since (h_1 XOR B2) ∈ {6,7}^16
(the invariant is preserved by the XOR with the {0,1}^16 chaining value), the
output stays in INV^16, so the constraint *is* a 16-bit equality between two
INV^16 values. Probability per (B1, B2) pair ≈ 2^-16, so per fixed B1 we expect
about one matching B2 in 2^16 trials. Iterating B1 ∈ INV^16 quickly finds a
preimage; in practice the very first B1 worked (~3 s).

Total online queries: 1 (just the final submission).
"""

import json
import socket
import sys
from hashlib import sha512
from itertools import product
from pathlib import Path

# Re-use the chall.py's MyHash by importing it directly. The chall file is
# named "13393.py" which isn't a valid Python identifier — load it via runpy.
import runpy

CHALL_PATH = Path(__file__).with_name("13393.py")

# Importing 13393.py would normally call listener.start_server() and block. We
# only need the MyHash class definition; replace utils.listener with a stub
# that swallows the start_server call.
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools"))
import utils.listener as _real_listener  # noqa: E402

_real_start = _real_listener.start_server
_real_listener.start_server = lambda *a, **kw: None
ns = runpy.run_path(str(CHALL_PATH), run_name="__not_main__")
_real_listener.start_server = _real_start

MyHash = ns["MyHash"]

HOST = "socket.cryptohack.org"
PORT = 13393
TIMEOUT = 30


def make_inv(idx: int) -> bytes:
    """Map a 16-bit index to a unique 8-byte block whose 16 nibbles are all in {6,7}."""
    return bytes(
        0x66 | (((idx >> (2 * i)) & 1) << 4) | ((idx >> (2 * i + 1)) & 1)
        for i in range(8)
    )


def find_zero_preimage() -> bytes:
    """Search for a 2-block content B1||B2 (each in INV^16) whose MyHash is 0^8."""
    print("[*] Searching INV^16 x INV^16 (2-block) for a hash-zero preimage...")
    ZERO = b"\x00" * 8
    for b1_idx in range(1 << 16):
        B1 = make_inv(b1_idx)
        for b2_idx in range(1 << 16):
            B2 = make_inv(b2_idx)
            content = B1 + B2
            if MyHash(content).digest() == ZERO:
                print(f"[+] hit at B1_idx={b1_idx}, B2_idx={b2_idx}")
                return content
        if b1_idx % 4 == 3:
            print(f"    ...no hit for first {b1_idx + 1} B1 values, continuing")
    raise RuntimeError("no 2-block preimage found")


def open_session():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # "Can you cryptanalyse this cryptohash?\n"
    return sock, f


def main() -> None:
    preimage = find_zero_preimage()
    print(f"[+] preimage      : {preimage.hex()}")
    print(f"[+] MyHash(preimg): {MyHash(preimage).digest().hex()}")

    sock, f = open_session()
    try:
        f.write((json.dumps({"option": "hash", "data": preimage.hex()}) + "\n").encode())
        line = f.readline()
        resp = json.loads(line.decode())
        print(f"[+] server response: {resp}")
        if "flag" in resp:
            print()
            print("FLAG:", resp["flag"])
    finally:
        sock.close()


if __name__ == "__main__":
    main()
