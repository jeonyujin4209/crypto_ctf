"""
Curveball (100pts) — EC / Signatures

Server pseudocode:
    Q = packet['generator'] * packet['private_key']
    if Q matches www.bing.com's stored public key:
        return FLAG

The server **does not validate** that `packet['generator']` is the standard
P256 base point — it accepts any (x, y) and uses it as g. Also rejects
abs(d) == 1 but allows d = 2.

Trick: pick d = 2 and craft g = bing_pubkey · inverse(d, n) on the curve.
Then server computes Q = g · d = bing_pubkey · inverse(2, n) · 2 = bing_pubkey.
Match → server returns the flag.
"""
import json
import socket
import time

from ecdsa.ecdsa import generator_256
from ecdsa import ellipticcurve, NIST256p

HOST = "socket.cryptohack.org"
PORT = 13382


def recv_until(sock, max_wait=2.0):
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


def main():
    n = NIST256p.order  # P256 group order
    bing_x = 0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531
    bing_y = 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A

    G = generator_256
    bing_pub = ellipticcurve.Point(G.curve(), bing_x, bing_y, n)

    d = 2
    inv_d = pow(d, -1, n)
    g_point = inv_d * bing_pub
    print(f"[*] crafted g = inv(2)·bing_pub = ({hex(g_point.x())[:20]}..., ...)")

    # Sanity check locally: g·d should equal bing_pub
    Q = d * g_point
    assert Q.x() == bing_x and Q.y() == bing_y, "local sanity failed"
    print("[+] local check ok: g·d == bing_pub")

    payload = {
        "private_key": int(d),
        "host": "www.bing.com",
        "curve": "secp256r1",
        "generator": [int(g_point.x()), int(g_point.y())],
    }

    sock = socket.create_connection((HOST, PORT))
    recv_until(sock, 2.0)  # greeting
    sock.send((json.dumps(payload) + "\n").encode())
    reply = recv_until(sock, 3.0)
    sock.close()
    print("[+] server:", reply.strip())


if __name__ == "__main__":
    main()
