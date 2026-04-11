"""
PriMeD5 (100pts) - Hash Functions / Collisions

The server signs primes via RSA-PKCS1v15 over MD5. The verifier accepts any
integer `p` plus a valid signature on MD5(long_to_bytes(p)), then computes
gcd(a, p) to reveal the first gcd(a, p) bytes of the flag.

Since p is asserted prime by the server only in the signing path, the check
path has no primality test - if we can get a signature that verifies
against a *composite* n whose MD5 matches some *prime* p we signed, we pass
the verifier. Then gcd(a, n) can be a huge proper divisor of n (just pick
a = n // smallest_prime_factor(n)), which trivially exceeds len(flag) and
leaks the whole flag.

Attack:
  1. Use Marc Stevens' fastcoll to find (m1, m2), 128 bytes each, with
     md5(m1) == md5(m2), iterating until one of {int.from_bytes(m1, "big"),
     int.from_bytes(m2, "big")} is prime and the other composite.
  2. Call `sign` with prime=int(prime_bytes) → server returns sig on MD5.
  3. Call `check` with prime=int(comp_bytes), signature=sig, a=comp/p_small
     where p_small is any prime factor of `comp` (trial-divide a few small
     primes; almost any composite has a factor ≤ 2^20). Then gcd(a, comp)
     = a, which is ~1024 bits, covering the whole flag.

See find_collision.py for the search script. It caches the result to
collision.json.
"""
import hashlib
import json
import os
import re
import socket
import time

from sympy import factorint, isprime


HOST = "socket.cryptohack.org"
PORT = 13392
TIMEOUT = 15


def recv_until_json(sock, max_wait=3.0):
    sock.settimeout(0.5)
    data = b""
    end = time.time() + max_wait
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            end = time.time() + 0.5
        except socket.timeout:
            if data:
                break
    return data.decode("utf-8", errors="replace")


def extract_jsons(text):
    out = []
    depth = 0
    start = None
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    out.append(json.loads(text[start : i + 1]))
                except json.JSONDecodeError:
                    pass
                start = None
    return out


def connect():
    s = socket.create_connection((HOST, PORT))
    s.settimeout(TIMEOUT)
    recv_until_json(s, 2.0)  # greeting
    return s


def send(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())
    return recv_until_json(sock, 3.0)


def small_factor(n, trial_limit=2 ** 20):
    """Return the smallest prime factor of n found by trial division up to
    trial_limit, or None if none found (n may be prime or have only large
    factors)."""
    if n % 2 == 0:
        return 2
    p = 3
    while p * p <= n and p <= trial_limit:
        if n % p == 0:
            return p
        p += 2
    return None


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "collision.json")) as f:
        data = json.load(f)
    prime_int = int(data["prime_int"])
    comp_int = int(data["composite_int"])
    assert isprime(prime_int), "cached 'prime' isn't prime"
    assert not isprime(comp_int), "cached 'composite' is actually prime"
    print(f"[+] prime bit length = {prime_int.bit_length()}")
    print(f"[+] comp  bit length = {comp_int.bit_length()}")

    p_small = small_factor(comp_int)
    assert p_small is not None, "cached composite has no small factor; regenerate"
    print(f"[+] smallest prime factor of composite = {p_small}")
    # Use a = p_small directly: gcd(p_small, comp) = p_small. As long as
    # p_small >= len(flag), flag[:p_small] reveals the entire flag. p_small
    # also fits easily inside the server's 1024-byte message limit.
    a_val = p_small
    print(f"[+] a = {a_val} (gcd with comp will equal {a_val})")

    # --- talk to server ---
    print()
    print("[*] Connecting to PriMeD5 server...")
    sock = connect()

    print("[1] sign(prime)")
    reply = send(sock, {"option": "sign", "prime": str(prime_int)})
    print("    server:", reply.strip())
    js = extract_jsons(reply)
    sig_hex = next(j["signature"] for j in js if "signature" in j)
    print(f"    sig = {sig_hex[:30]}... ({len(sig_hex)//2} bytes)")

    print("[2] check(composite, signature, a)")
    reply = send(
        sock,
        {
            "option": "check",
            "prime": str(comp_int),
            "signature": sig_hex,
            "a": str(a_val),
        },
    )
    print("    server:", reply.strip())
    sock.close()


if __name__ == "__main__":
    main()
