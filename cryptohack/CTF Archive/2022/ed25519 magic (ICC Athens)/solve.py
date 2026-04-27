"""
Two ed25519 attacks against Warner's `python-ed25519` (SUPERCOP ref10).

Level 1 — signature malleability (S + L):
  ref10 verifier checks `sm[63] & 0xE0 == 0` (S < 2^253) but does NOT check S < L.
  Given a valid sig (R, S), the value (R, S+L) is also valid because the verifier
  reduces S mod L internally via the scalar mul. S < L, so S+L < 2L < 2^253 → high
  bits clean. (R, S+L) != (R, S) → bypasses the != sig check.

Level 2 — magic signature with identity verifying key:
  The library does NOT reject identity (0,1) on decode, and does NOT do cofactored
  verification. Verifier computes R' = h*A + s*B and checks R' == R.
    A = identity → h*A = identity for ANY h (so M is irrelevant)
    s = 0       → s*B = identity
    R = identity → R' = identity = R ✓
  Encoding of identity in Ed25519: y=1, x=0 → little-endian y with sign bit = 0
  → bytes 0x01 || 0x00*31.
"""
import base64
import sys
from pwn import remote, context

L = 2**252 + 27742317777372353535851937790883648493


def attack_level1(io):
    io.recvuntil(b"Signature:\n")
    sig = base64.b64decode(io.recvline().strip())
    R, S = sig[:32], sig[32:]
    S_int = int.from_bytes(S, "little")
    S_new = S_int + L
    assert S_new < 2**253
    new_sig = R + S_new.to_bytes(32, "little")
    assert new_sig != sig
    io.recvuntil(b"Enter new signature:\n")
    io.sendline(base64.b64encode(new_sig))


def attack_level2(io):
    vk_bytes = b"\x01" + b"\x00" * 31  # encoded identity (0, 1)
    sig_bytes = vk_bytes + b"\x00" * 32  # R = identity, S = 0
    io.recvuntil(b"Enter verifying key:\n")
    io.sendline(base64.b64encode(vk_bytes))
    io.recvuntil(b"Enter signature:\n")
    io.sendline(base64.b64encode(sig_bytes))


def main():
    context.log_level = "info"
    HOST, PORT = "archive.cryptohack.org", 31144
    io = remote(HOST, PORT)
    attack_level1(io)
    attack_level2(io)
    rest = io.recvall(timeout=5).decode(errors="replace")
    print(rest)
    io.close()


if __name__ == "__main__":
    main()
