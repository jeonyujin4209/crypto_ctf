"""
Static Client (DH / Man-In-The-Middle) — POC solver

Bob has a *static* long-term Diffie-Hellman private key `b`. Anyone connecting
sees an Alice→Bob handshake (in the standard 1024-bit safe-prime group) plus
the resulting AES-CBC-encrypted flag — but they cannot read the flag because
Bob's `b` is secret.

The bug: when *we* connect afterwards we get to choose the {p, g, A} that Bob
runs DH with, and Bob still uses the *same* static `b`. So we send a custom
prime p_smooth chosen so that p_smooth − 1 is B-smooth, ask Bob for
B' = g^b mod p_smooth, and recover `b` via Pohlig-Hellman in seconds. With
`b` in hand we redo the original handshake's shared secret = A_alice^b mod
p_orig and decrypt the eavesdropped flag.

Workflow:
  1. Connect once, parse the eavesdropped (p_orig, g_orig, A_alice, B_bob,
     iv, encrypted) tuple.
  2. Generate a smooth prime p_smooth such that g=2 is a primitive root.
  3. Connect again, send {"p": p_smooth, "g": "0x2", "A": "0x2"}, receive
     B_smooth = 2^b mod p_smooth.
  4. b = discrete_log(p_smooth, B_smooth, 2)  (Pohlig-Hellman, fast).
  5. shared = A_alice^b mod p_orig → AES-CBC decrypt → FLAG.

Same script vs. socket.cryptohack.org:13373 (or any compatible server) just
needs HOST = "socket.cryptohack.org".
"""

import hashlib
import json
import random
import re
import socket
import sys
import time

from Crypto.Cipher import AES
from sympy import discrete_log, factorint, isprime, nextprime

HOST = "socket.cryptohack.org"
PORT = 13373
TIMEOUT = 10


def connect():
    s = socket.create_connection((HOST, PORT))
    s.settimeout(TIMEOUT)
    return s


def recv_until_quiet(s, max_wait=2.0):
    """Read everything the server has buffered up to ~max_wait seconds idle."""
    data = b""
    s.settimeout(0.5)
    end_at = time.time() + max_wait
    while time.time() < end_at:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
            end_at = time.time() + 0.5
        except socket.timeout:
            if data:
                break
    s.settimeout(TIMEOUT)
    return data.decode(errors="replace")


def extract_jsons(text: str):
    return [json.loads(m.group()) for m in re.finditer(r"\{[^{}]+\}", text)]


def make_smooth_prime(min_bits: int = 800, randomise: int = 30):
    """Build a prime p such that p-1 is B-smooth and 2 is a primitive root."""
    while True:
        n = 2
        q = 2
        while n.bit_length() < min_bits:
            q = int(nextprime(q))
            n *= q
        for _ in range(random.randint(0, randomise)):
            n *= random.choice([2, 3, 5, 7, 11, 13])
        p = n + 1
        if not isprime(p):
            continue
        # Check 2 is a primitive root mod p, i.e. has order p-1.
        factors = factorint(n)  # n = p - 1
        if all(pow(2, n // f, p) != 1 for f in factors):
            return p


def main() -> None:
    # Step 1: eavesdrop
    print("[1] Eavesdropping handshake...")
    s = connect()
    text = recv_until_quiet(s, max_wait=2.0)
    s.close()
    js = extract_jsons(text)
    if len(js) < 3:
        print("[-] expected 3 JSON messages on first connect, got:", text, file=sys.stderr)
        sys.exit(1)
    alice = js[0]
    bob = js[1]
    msg = js[2]
    p_orig = int(alice["p"], 16)
    g_orig = int(alice["g"], 16)
    A_alice = int(alice["A"], 16)
    B_bob = int(bob["B"], 16)
    iv = bytes.fromhex(msg["iv"])
    encrypted = bytes.fromhex(msg["encrypted"])
    print(f"    p_orig    = {p_orig.bit_length()}-bit")
    print(f"    g_orig    = {g_orig}")
    print(f"    A_alice   = {hex(A_alice)[:20]}...")
    print(f"    B_bob     = {hex(B_bob)[:20]}...")

    # Step 2: build smooth prime
    # Must be LARGER than p_orig so that dlog recovers the full b (not
    # merely b mod (p_smooth - 1), which would truncate the high bits).
    print("[2] Generating smooth prime (p-1 is B-smooth, g = 2 is primitive root)...")
    p_smooth = make_smooth_prime(min_bits=p_orig.bit_length() + 16)
    print(f"    p_smooth  = {p_smooth.bit_length()}-bit")

    # Step 3: send malicious params and receive Bob's reply
    print("[3] Sending smooth prime to Bob...")
    s = connect()
    recv_until_quiet(s, max_wait=1.5)  # consume the per-connection eavesdrop
    payload = json.dumps({"p": hex(p_smooth), "g": "0x2", "A": "0x2"}).encode() + b"\n"
    s.send(payload)
    reply = recv_until_quiet(s, max_wait=2.0)
    s.close()
    rj = extract_jsons(reply)
    B_smooth = None
    for j in rj:
        if "B" in j:
            B_smooth = int(j["B"], 16)
            break
    if B_smooth is None:
        print("[-] no B in reply:", reply, file=sys.stderr)
        sys.exit(1)
    print(f"    B_smooth  = {hex(B_smooth)[:20]}...")

    # Step 4: discrete log on smooth group
    print("[4] Pohlig-Hellman dlog (sympy.discrete_log)...")
    b = int(discrete_log(p_smooth, B_smooth, 2))
    print(f"    b         = {b}")

    # Verify against the eavesdropped B_bob
    B_check = pow(2, b, p_orig)
    print(f"    g^b mod p_orig matches B_bob? {B_check == B_bob}")
    assert B_check == B_bob, "recovered b does not match eavesdropped B; the server may not be using a static key"

    # Step 5: derive shared secret and decrypt
    shared = pow(A_alice, b, p_orig)
    key = hashlib.sha1(str(shared).encode("ascii")).digest()[:16]
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
    print()
    print("FLAG:", plaintext.decode(errors="replace").rstrip("\x00"))


if __name__ == "__main__":
    main()
