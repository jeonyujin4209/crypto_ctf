"""
Twin Keys (100pts) — Hash Functions / Collisions

The server stores a {key: flag_bit} dict and unlocks only when exactly ONE
inserted key starts with `KEY_START = b"CryptoHack Secure Safe"` AND the two
keys collide under a custom XOR scrambler on top of MD5.

XOR scrambler analysis:

    def unlock(self):
        ...
        h1 = MD5(k1); h2 = MD5(k2)
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), magic2)

Simplify the XOR expressions (both reduce to trivial identities):

    h1' = magic1 ^ h1        (every "inner" term cancels to h1 or h1^h2)
    h2' = h2 ^ magic2        (h1' cancels itself out — h1 is even-multiplicity)

So each iteration XORs magic1 into h1 and magic2 into h2. The iteration
count is  N = 2^k - 2  for  k in [2, 10], which is **always even**, so after
the loop h1 == MD5(k1) and h2 == MD5(k2) — the scrambler is a no-op.

Therefore: unlock ⟺ MD5(k1) == MD5(k2) ∧ exactly one startswith KEY_START.

This is an MD5 chosen-prefix collision. We precompute it offline with
HashClash's fastcpc.sh (see infra/Dockerfile.hashclash and the work dir
./hashclash_work/). Given prefix1.bin = KEY_START and prefix2.bin = 22 bytes
NOT starting with "CryptoHack Secure Safe", HashClash outputs two 200~600
byte suffixes appended to each prefix so the full messages collide under
MD5.

Once we have the two colliding messages, insertion + unlock is trivial.
"""

import hashlib
import json
import os
import socket
import time


HOST = "socket.cryptohack.org"
PORT = 13397
KEY_START = b"CryptoHack Secure Safe"

# cpc.sh (HashClash static release) writes `<input>.coll` files next to the
# input files. Look for `file1.bin.coll` and `file2.bin.coll` in the work
# directory.
HASHCLASH_DIRS = [
    os.path.expanduser(r"~/AppData/Local/Temp/twin-keys-test"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashclash_work"),
]


def load_collision():
    """Find HashClash's output messages."""
    for d in HASHCLASH_DIRS:
        # cpc.sh output: file1.bin.coll, file2.bin.coll
        f1 = os.path.join(d, "file1.bin.coll")
        f2 = os.path.join(d, "file2.bin.coll")
        if os.path.exists(f1) and os.path.exists(f2):
            return open(f1, "rb").read(), open(f2, "rb").read(), ("file1.bin.coll", "file2.bin.coll")
        # poc_no.sh output
        f1 = os.path.join(d, "collision1.bin")
        f2 = os.path.join(d, "collision2.bin")
        if os.path.exists(f1) and os.path.exists(f2):
            return open(f1, "rb").read(), open(f2, "rb").read(), ("collision1.bin", "collision2.bin")
    raise FileNotFoundError(
        "No collision files found. Run cpc_patched.sh with file1.bin=KEY_START "
        "and file2.bin=<non-KEY_START 22 bytes>."
    )


def recv_json_lines(sock, max_wait=3.0):
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


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())
    return recv_json_lines(sock, 3.0)


def main():
    m1, m2, names = load_collision()
    assert m1 != m2
    assert hashlib.md5(m1).digest() == hashlib.md5(m2).digest(), "MD5 collision broken"
    s1 = m1.startswith(KEY_START)
    s2 = m2.startswith(KEY_START)
    assert s1 ^ s2, f"exactly one must start with KEY_START, got s1={s1}, s2={s2}"
    print(f"[+] loaded collision pair {names}")
    print(f"    len(m1) = {len(m1)},  startswith KEY_START = {s1}")
    print(f"    len(m2) = {len(m2)},  startswith KEY_START = {s2}")
    print(f"    md5     = {hashlib.md5(m1).hexdigest()}")

    # Ensure both are <= 1024 bytes (server limit)
    assert len(m1) <= 1024 and len(m2) <= 1024, "messages exceed server limit"

    print()
    print("[*] Connecting to Twin Keys...")
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(15)
    recv_json_lines(sock, 1.5)  # greeting

    print("[1] insert_key(m1)")
    r = send_json(sock, {"option": "insert_key", "key": m1.hex()})
    print("    ", r.strip())

    print("[2] insert_key(m2)")
    r = send_json(sock, {"option": "insert_key", "key": m2.hex()})
    print("    ", r.strip())

    print("[3] unlock()")
    r = send_json(sock, {"option": "unlock"})
    print("    ", r.strip())
    sock.close()


if __name__ == "__main__":
    main()
