"""
Bruce Schneier's Password Part 2 (40pts) — sum == prod with int64 overflow

check() requires sum(ord) == prod(ord) AND sum is prime. prod is computed
via numpy int64 (wraps on overflow). For a password of ~10-40 chars, the
sum is at most ~4800, so we need prod-mod-2^64-signed to equal a small
positive prime that's also the sum.

Brute force random passwords until we find one where the int64 prod wraps
to match the sum (and sum is prime).
"""
import json
import random
import socket
import string
import numpy as np
from Crypto.Util.number import isPrime

HOST = "socket.cryptohack.org"
PORT = 13401

ALPHA = string.ascii_letters + string.digits + "_"


def find_password():
    rng = random.Random(0xBADF00D)
    tries = 0
    while True:
        L = rng.randint(8, 40)
        body = "".join(rng.choices(ALPHA, k=L))
        pw = "Aa1" + body  # guaranteed upper+lower+digit
        arr = np.array(list(map(ord, pw)), dtype=np.int64)
        s = arr.sum()
        p = arr.prod()
        tries += 1
        if s == p and isPrime(int(s)):
            print(f"[+] found after {tries} tries  len={len(pw)}  sum={int(s)}  prod={int(p)}")
            return pw
        if tries % 200000 == 0:
            print(f"  [{tries}] last pw={pw}  s={int(s)}  p={int(p)}")


def recv_until(sock, end=b"\n", max_wait=5.0):
    sock.settimeout(max_wait)
    buf = b""
    while not buf.endswith(end):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main():
    pw = find_password()
    print(f"[*] password = {pw!r}")

    sock = socket.create_connection((HOST, PORT))
    greeting = recv_until(sock)
    print(f"[*] greeting: {greeting.decode(errors='replace').strip()}")
    sock.send((json.dumps({"password": pw}) + "\n").encode())
    resp = recv_until(sock)
    sock.close()
    print(f"[+] {resp.decode(errors='replace').strip()}")


if __name__ == "__main__":
    main()
