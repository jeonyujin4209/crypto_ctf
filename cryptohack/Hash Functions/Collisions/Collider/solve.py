"""
Collider (Hash Functions / Collisions) — POC solver

Server (13389.py) keeps a dict { md5(doc) : doc }, pre-seeded with two physics
blurbs. On every "document" message:
  - if md5(doc) is already in the dict
      - and doc == stored:    "Document already exists"
      - else:                  "Document system crash, leaking flag: <FLAG>"
  - else: store doc and continue (max 5 documents).

So all we need is two distinct messages with the same MD5. MD5 collision
resistance is broken (Wang/Yu 2004), and we can hard-code the very first known
identical-prefix collision pair to mount this attack offline:

  M1, M2  : two 128-byte messages, identical except for a few diff'ing bytes.
  md5(M1) == md5(M2) == 79054025255fb1a26e4bc422aef54eb4

We submit M1 (gets stored) and then M2 (collision detected → flag).
"""

import hashlib
import json
import socket
import sys

HOST = "socket.cryptohack.org"
PORT = 13389
TIMEOUT = 30

# Wang/Yu 2004 MD5 collision pair (identical-prefix collision, 128 bytes each)
M1_HEX = (
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a88393 96f9652b6ff72a70"
).replace(" ", "")
M2_HEX = (
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a88393 96f965ab6ff72a70"
).replace(" ", "")

EXPECTED_MD5 = "79054025255fb1a26e4bc422aef54eb4"


def open_session():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # "Give me a document to store\n"
    return sock, f


def send(f, doc: bytes) -> dict:
    f.write((json.dumps({"document": doc.hex()}) + "\n").encode())
    line = f.readline()
    return json.loads(line.decode())


def main() -> None:
    M1 = bytes.fromhex(M1_HEX)
    M2 = bytes.fromhex(M2_HEX)
    assert M1 != M2, "M1 and M2 must be different"
    assert hashlib.md5(M1).hexdigest() == hashlib.md5(M2).hexdigest() == EXPECTED_MD5, \
        f"collision pair invalid: md5(M1)={hashlib.md5(M1).hexdigest()}, " \
        f"md5(M2)={hashlib.md5(M2).hexdigest()}"
    print(f"[+] Wang collision pair OK, md5 = {EXPECTED_MD5}")

    sock, f = open_session()
    try:
        # Step 1: store M1
        r1 = send(f, M1)
        print(f"[+] sent M1 → {r1}")
        if "success" not in r1:
            print("unexpected (M1 might already be in the seed dict)", file=sys.stderr)

        # Step 2: send M2 — its md5 collides with M1's, server leaks flag
        r2 = send(f, M2)
        print(f"[+] sent M2 → {r2}")

        # Flag is embedded in the "error" string
        flag_msg = r2.get("error", "")
        if "leaking flag" in flag_msg:
            flag = flag_msg.split("leaking flag:", 1)[1].strip()
            print()
            print("FLAG:", flag)
        else:
            print("forge failed:", r2)
            sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
