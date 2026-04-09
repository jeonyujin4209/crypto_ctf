"""
Mixed Up (Hash Functions / Pre-image attacks) — POC solver

Server (13402.py) accepts {"option":"mix","data":<hex>} and returns
{"mixed": sha256(very_mixed).hexdigest()}, where:

    mixed_and = FLAG & data                  # bytewise
    mixed_xor = FLAG XOR data XOR random     # random destroys this branch
    very_mixed[k] = mixed_xor[mixed_and[k] % n]   # n = len(FLAG)

shuffle picks one byte of mixed_xor per position k, indexed by mixed_and[k] % n.

Attack — bit oracle via "all-equal byte" detection
---------------------------------------------------
Send data with a single position j set to (1 << b) and zeros elsewhere.
Then mixed_and[k] = 0 everywhere except mixed_and[j] = FLAG[j] & (1 << b),
which is either 0 (bit b of FLAG[j] is 0) or (1 << b) (bit is 1).

If bit b of FLAG[j] == 0:
    very_mixed[k] = mixed_xor[0]  for all k         → very_mixed = byte * n
    The sha256 lies in the 256-element set { sha256(b * n) : b in 0..255 }.

If bit b of FLAG[j] == 1:
    very_mixed[k] = mixed_xor[0]  for k != j
    very_mixed[j] = mixed_xor[(1 << b) % n]   ← independently random byte
    The sha256 is (essentially never) in that 256-element set.

So one query reveals one bit. n × 8 queries recover the FLAG.

Sanity: needs (1<<b) % n != 0 for all b in 0..7, i.e. n must not divide any
power of 2 ≤ 128. n = 39 is odd, so safe. (Add an assertion if you change n.)

False-positive control: when bit b of FLAG[j] is actually 1, mixed_xor[0] and
mixed_xor[(1<<b) % n] are independent random bytes, so they collide with
probability 1/256, in which case very_mixed *is* single-byte and our test
mis-classifies the bit as 0. We repeat each bit query K times and call the bit
1 iff *any* query returns a hash outside the precomputed set. With K = 3 the
miscall probability per bit is 1/256^3 ≈ 6e-8 (effectively zero).

Total queries: K × 8 × n  ≈ 936 for n=39, K=3. Same script, different HOST,
retrieves the real flag.
"""

import json
import socket
from hashlib import sha256

HOST = "127.0.0.1"
PORT = 13402
TIMEOUT = 30


def open_session():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # "Oh no, how are you going to unmix this?\n"
    return sock, f


def query(f, data: bytes) -> str:
    f.write((json.dumps({"option": "mix", "data": data.hex()}) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    resp = json.loads(line.decode())
    if "mixed" not in resp:
        raise RuntimeError(f"unexpected response: {resp}")
    return resp["mixed"]


def main() -> None:
    # Placeholder FLAG length on the local listener is 39. For the real server
    # the length may differ — see /find_flag_length() in MDFlag, but here the
    # server pads short input with urandom rather than rejecting, so length
    # discovery has to be done differently (e.g. try several lengths and check
    # which yields a self-consistent reconstruction).
    n = 39
    assert all((1 << b) % n != 0 for b in range(8)), "n must not divide any 2^b<=128"

    # Precompute the 256 hashes of (single_byte * n)
    single_byte_hashes = {sha256(bytes([b]) * n).hexdigest() for b in range(256)}

    REPEAT = 3  # K — bit miscall prob ~ 1/256^K
    sock, f = open_session()
    try:
        flag = bytearray(n)
        for j in range(n):
            for b in range(8):
                bit_is_one = False
                for _ in range(REPEAT):
                    data = bytearray(n)
                    data[j] = 1 << b
                    h = query(f, bytes(data))
                    if h not in single_byte_hashes:
                        bit_is_one = True
                        break  # one "outside" query is sufficient
                if bit_is_one:
                    flag[j] |= 1 << b
            ch = chr(flag[j]) if 32 <= flag[j] < 127 else "?"
            print(f"[{j:2d}] = 0x{flag[j]:02x}  {ch!r}")
        print()
        print("FLAG:", flag.decode(errors="replace"))
    finally:
        sock.close()


if __name__ == "__main__":
    main()
