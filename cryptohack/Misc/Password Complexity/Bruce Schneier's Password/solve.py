"""
Bruce Schneier's Password (30pts) — numpy int64 overflow

check() requires:
  - password matches \\w* ASCII (letters/digits/underscore)
  - at least one digit, one upper, one lower
  - sum of ord values is prime
  - product of ord values is prime

Product-of-many-positive-integers-being-prime is impossible, UNLESS numpy
int64 OVERFLOWS and wraps to a prime. The code converts to Python int via
int(array.prod()), so negative wraps stay negative (isPrime returns False),
but if the wrapped signed value is a positive prime, check() returns FLAG.

Strategy: start with "Aa1" (satisfies upper/lower/digit), append random
\\w characters until both sum and prod-mod-2^64 (signed) are primes.
"""
import json
import random
import socket
import string
import numpy as np
from Crypto.Util.number import isPrime

HOST = "socket.cryptohack.org"
PORT = 13400

ALPHA = string.ascii_letters + string.digits + "_"


def find_password():
    rng = random.Random(0xC0FFEE)
    tries = 0
    while True:
        # random length between 10 and 40
        L = rng.randint(10, 40)
        body = "".join(rng.choices(ALPHA, k=L))
        pw = "Aa1" + body  # guaranteed upper+lower+digit
        arr = np.array(list(map(ord, pw)), dtype=np.int64)
        s = int(arr.sum())
        p = int(arr.prod())
        tries += 1
        if p > 0 and isPrime(s) and isPrime(p):
            print(f"[+] found after {tries} tries  len={len(pw)}  sum={s}  prod={p}")
            return pw
        if tries % 100000 == 0:
            print(f"  [{tries}] last pw={pw}  s={s}  p={p}")


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
