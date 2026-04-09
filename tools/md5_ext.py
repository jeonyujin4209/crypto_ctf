"""
Pure-Python MD5 with length-extension support.

Provides:
  md5_pad(msg_len_bytes) -> bytes
      Compute the padding bytes that hashlib.md5 would append for a message
      of the given length.

  md5_continue(prev_digest_hex, prev_msg_len_bytes, extension) -> str
      Length-extension primitive: returns hashlib.md5(M || pad(M) || extension)
      .hexdigest(), given only md5(M).hexdigest() and len(M).

The MD5 compression function is implemented from RFC 1321. We import nothing
from hashlib for the extension path so the result is independent of hashlib's
internals (we cross-check against hashlib.md5 in self_test()).
"""

from __future__ import annotations

import struct

# --- MD5 constants -----------------------------------------------------------

_S = (
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
)

_K = tuple(int(abs(__import__("math").sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF
           for i in range(64))

_INITIAL = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


def _leftrotate(x: int, c: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF


def _compress(state: tuple[int, int, int, int], block: bytes) -> tuple[int, int, int, int]:
    assert len(block) == 64
    M = struct.unpack("<16I", block)
    a, b, c, d = state
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & 0xFFFFFFFF & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & 0xFFFFFFFF & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d & 0xFFFFFFFF))
            g = (7 * i) % 16
        f = (f + a + _K[i] + M[g]) & 0xFFFFFFFF
        a = d
        d = c
        c = b
        b = (b + _leftrotate(f, _S[i])) & 0xFFFFFFFF
    return (
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
    )


def md5_pad(msg_len_bytes: int) -> bytes:
    """Bytes that MD5 appends to a message of length `msg_len_bytes`."""
    pad = b"\x80"
    # We must have (msg_len_bytes + 1 + zeros + 8) % 64 == 0
    zeros = (-(msg_len_bytes + 1 + 8)) % 64
    pad += b"\x00" * zeros
    pad += struct.pack("<Q", msg_len_bytes * 8)
    return pad


def _state_from_hex(hex_digest: str) -> tuple[int, int, int, int]:
    raw = bytes.fromhex(hex_digest)
    assert len(raw) == 16
    return struct.unpack("<4I", raw)


def _hex_from_state(state: tuple[int, int, int, int]) -> str:
    return struct.pack("<4I", *state).hex()


def md5(message: bytes) -> str:
    """Standalone MD5 (so we can self-test against hashlib.md5)."""
    state = _INITIAL
    padded = message + md5_pad(len(message))
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i : i + 64])
    return _hex_from_state(state)


def md5_continue(prev_digest_hex: str, prev_msg_len_bytes: int, extension: bytes) -> str:
    """
    Length-extension primitive.

    Returns hashlib.md5(M || pad(M) || extension).hexdigest() given only
    md5(M).hexdigest() and len(M). M itself is unknown.

    The trick: md5 is a Merkle-Damgard construction. After processing M followed
    by pad(M), the running state equals the published digest. We can therefore
    resume the computation by setting our state to that digest, processing
    `extension` as additional message bytes, and finalising with a fresh
    pad whose length encoding reflects the *total* message length
    prev_msg_len_bytes + len(pad(M)) + len(extension).
    """
    state = _state_from_hex(prev_digest_hex)
    pad_M_len = len(md5_pad(prev_msg_len_bytes))
    pre_processed = prev_msg_len_bytes + pad_M_len  # multiple of 64

    # Pad the extension assuming the total message has length
    #     pre_processed + len(extension)
    new_total_len = pre_processed + len(extension)
    padded_ext = extension + md5_pad(new_total_len)

    for i in range(0, len(padded_ext), 64):
        state = _compress(state, padded_ext[i : i + 64])
    return _hex_from_state(state)


# --- Self-test ---------------------------------------------------------------

def self_test() -> None:
    import hashlib

    # 1. md5() matches hashlib for a few inputs
    for m in (b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"hello world", b"x" * 1000):
        assert md5(m) == hashlib.md5(m).hexdigest(), m

    # 2. md5_continue gives md5(M || pad(M) || ext) for known M
    for prefix_len in (0, 1, 16, 46, 55, 56, 63, 64, 100, 183, 256):
        for ext_len in (0, 1, 9, 17, 64, 100):
            M = bytes((i * 7) & 0xFF for i in range(prefix_len))
            ext = bytes((i * 13 + 5) & 0xFF for i in range(ext_len))
            h_M = hashlib.md5(M).hexdigest()
            full = M + md5_pad(len(M)) + ext
            expected = hashlib.md5(full).hexdigest()
            got = md5_continue(h_M, len(M), ext)
            assert got == expected, (prefix_len, ext_len, expected, got)

    print("md5_ext self-test OK")


if __name__ == "__main__":
    self_test()
