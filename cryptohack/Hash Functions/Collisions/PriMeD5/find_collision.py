"""
PriMeD5 helper: loop fastcoll until we find an MD5 collision pair (m1, m2)
where ONE side is a prime and the OTHER is composite. We'll sign the prime
via the server and reuse the signature to "verify" the composite, which
has a large proper divisor → flag recovered via gcd.

Prints two hex-encoded 128-byte messages to stdout and writes them to
collision.json for the solver to consume.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

from sympy import isprime

FASTCOLL = os.environ.get(
    "FASTCOLL",
    os.path.expanduser(r"~/AppData/Local/Temp/fastcoll/fastcoll_v1.0.0.5.exe"),
)


def one_collision():
    with tempfile.TemporaryDirectory() as td:
        m1p = os.path.join(td, "m1.bin")
        m2p = os.path.join(td, "m2.bin")
        subprocess.run(
            [FASTCOLL, "-q", "-o", m1p, m2p],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        m1 = open(m1p, "rb").read()
        m2 = open(m2p, "rb").read()
    assert hashlib.md5(m1).digest() == hashlib.md5(m2).digest()
    assert m1 != m2
    return m1, m2


def main():
    t0 = time.time()
    attempts = 0
    while True:
        attempts += 1
        m1, m2 = one_collision()
        # long_to_bytes-compatible? First byte must be non-zero (fastcoll
        # produces this by default).
        if m1[0] == 0 or m2[0] == 0:
            continue
        n1 = int.from_bytes(m1, "big")
        n2 = int.from_bytes(m2, "big")
        # Need exactly one prime. Check the cheaper side first.
        p1 = isprime(n1)
        p2 = isprime(n2)
        dur = time.time() - t0
        print(
            f"[{attempts:4d}  {dur:6.1f}s]  "
            f"n1 prime={p1}  n2 prime={p2}",
            flush=True,
        )
        if p1 and not p2:
            prime_bytes, comp_bytes = m1, m2
            break
        if p2 and not p1:
            prime_bytes, comp_bytes = m2, m1
            break

    prime_int = int.from_bytes(prime_bytes, "big")
    comp_int = int.from_bytes(comp_bytes, "big")
    # Sanity: long_to_bytes(int) round-trips cleanly iff no leading zeros.
    assert prime_bytes[0] != 0 and comp_bytes[0] != 0

    out = {
        "prime_hex": prime_bytes.hex(),
        "composite_hex": comp_bytes.hex(),
        "prime_int": str(prime_int),
        "composite_int": str(comp_int),
        "attempts": attempts,
        "seconds": time.time() - t0,
    }
    with open("collision.json", "w") as f:
        json.dump(out, f, indent=2)
    print()
    print(f"[+] Done in {attempts} attempts, {out['seconds']:.1f}s")
    print(f"    prime bytes = {prime_bytes.hex()}")
    print(f"    comp bytes  = {comp_bytes.hex()}")
    print(f"    md5 match   = {hashlib.md5(prime_bytes).hexdigest()}")


if __name__ == "__main__":
    main()
