"""
Static Client 2 (DH / Group Theory) — POC solver

Bob now has a basic sanity-check on the {p, g, A} we send him: he rejects
small/non-prime moduli and rejects "obviously cooked" public values like
A = 2. Crucially, he still trusts whatever {p, g} we hand him AND he still
uses the same long-term static `b`. So the Static-Client-1 trick still
applies — we just have to dress up our request:

  • p_smooth: a prime such that p_smooth - 1 is B-smooth and bigger than the
    original 1536-bit modulus (so Pohlig-Hellman recovers the *full* b).
  • g = 2 (we ensure 2 is a primitive root of p_smooth).
  • A = 2^k mod p_smooth for some random k (NOT A = 2).

Bob replies with B_smooth = 2^b mod p_smooth, we run discrete_log to recover
b, then recompute the eavesdropped session key against the original prime.

Server: socket.cryptohack.org 13378
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
PORT = 13378
TIMEOUT = 10


def connect():
    s = socket.create_connection((HOST, PORT))
    s.settimeout(TIMEOUT)
    return s


def recv_all(s, max_wait=2.0):
    data = b""
    s.settimeout(0.5)
    end = time.time() + max_wait
    while time.time() < end:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
            end = time.time() + 0.5
        except socket.timeout:
            if data:
                break
    s.settimeout(TIMEOUT)
    return data.decode("utf-8", errors="replace")


def extract_jsons(text):
    return [json.loads(m.group()) for m in re.finditer(r"\{[^{}]+\}", text)]


def make_smooth_prime(min_bits=1550, randomise=30):
    """Build prime p with p-1 B-smooth such that 2 is a primitive root."""
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
        factors = factorint(n)
        if all(pow(2, n // f, p) != 1 for f in factors):
            return p


def main():
    # Step 1: eavesdrop the static handshake
    print("[1] Eavesdropping handshake...")
    s = connect()
    text = recv_all(s, max_wait=2.0)
    js = extract_jsons(text)
    if len(js) < 3:
        print("[-] expected 3 messages, got:", text, file=sys.stderr)
        sys.exit(1)
    alice = js[0]
    bob = js[1]
    msg = js[2]
    p_orig = int(alice["p"], 16)
    A_alice = int(alice["A"], 16)
    B_bob = int(bob["B"], 16)
    iv = bytes.fromhex(msg["iv"])
    encrypted = bytes.fromhex(msg["encrypted"])
    print(f"    p_orig    = {p_orig.bit_length()}-bit")
    print(f"    B_bob     = {hex(B_bob)[:20]}...")

    # Step 2: build smooth prime > p_orig
    print("[2] Generating smooth prime...")
    p_smooth = make_smooth_prime(min_bits=p_orig.bit_length() + 16)
    print(f"    p_smooth  = {p_smooth.bit_length()}-bit")

    # Step 3: send malicious params (A != 2 to dodge Bob's sanity check)
    print("[3] Sending parameters to Bob...")
    A_fake = pow(2, random.randint(2, p_smooth - 2), p_smooth)
    payload = json.dumps({
        "p": hex(p_smooth),
        "g": "0x2",
        "A": hex(A_fake),
    }).encode() + b"\n"
    s.send(payload)
    reply = recv_all(s, max_wait=3.0)
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

    # Step 4: Pohlig-Hellman dlog (sympy auto-PHs since p_smooth-1 is smooth)
    print("[4] Running discrete_log...")
    b = int(discrete_log(p_smooth, B_smooth, 2))
    print(f"    b = {b}")

    # Verify against the eavesdropped B_bob
    assert pow(2, b, p_orig) == B_bob, "recovered b does not match B_bob"

    # Step 5: derive shared secret and decrypt
    shared = pow(A_alice, b, p_orig)
    key = hashlib.sha1(str(shared).encode("ascii")).digest()[:16]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
    print()
    print("FLAG:", pt.decode(errors="replace").rstrip("\x00"))


if __name__ == "__main__":
    main()
