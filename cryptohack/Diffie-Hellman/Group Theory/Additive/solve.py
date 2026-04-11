"""
Additive (DH / Group Theory) — POC solver

Alice and Bob are running Diffie-Hellman in the *additive* group (Z/pZ, +)
instead of the multiplicative group. In additive notation, "g^x" means x·g
(repeated addition = multiplication mod p), so:

    A = a · g  (mod p)
    B = b · g  (mod p)
    shared = a · b · g  (mod p)

The DLP is now: given A, g, find a such that A = a·g. That's just
a = A · g⁻¹  (mod p) — instant. Even simpler, the shared secret is:

    shared = (A · B) · g⁻¹  (mod p)

Server: socket.cryptohack.org 13380
"""

import hashlib
import json
import re
import socket
import sys
import time

from Crypto.Cipher import AES

HOST = "socket.cryptohack.org"
PORT = 13380


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
    return data.decode("utf-8", errors="replace")


def extract_jsons(text):
    return [json.loads(m.group()) for m in re.finditer(r"\{[^{}]+\}", text)]


def main():
    s = socket.create_connection((HOST, PORT))
    text = recv_all(s, max_wait=3.0)
    s.close()

    js = extract_jsons(text)
    if len(js) < 3:
        print("[-] expected 3 messages, got:", text, file=sys.stderr)
        sys.exit(1)

    p = int(js[0]["p"], 16)
    g = int(js[0]["g"], 16)
    A = int(js[0]["A"], 16)
    B = int(js[1]["B"], 16)
    iv = bytes.fromhex(js[2]["iv"])
    ct = bytes.fromhex(js[2]["encrypted"])

    print(f"p = {p.bit_length()}-bit")
    print(f"g = {g}")

    # In the additive group: A = a*g, B = b*g, shared = a*b*g = (A*B)*g^(-1)
    g_inv = pow(g, -1, p)
    shared = (A * B) % p * g_inv % p

    # Verify: a = A * g_inv, then shared should equal a * B
    a = A * g_inv % p
    assert shared == a * B % p

    key = hashlib.sha1(str(shared).encode("ascii")).digest()[:16]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    print()
    print("FLAG:", pt.decode(errors="replace").rstrip("\x00"))


if __name__ == "__main__":
    main()
