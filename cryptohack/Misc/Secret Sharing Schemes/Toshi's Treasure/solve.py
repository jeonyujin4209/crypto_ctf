"""
Toshi's Treasure (150pts) — Shamir 5-of-6, adaptive fake share attack

The server gives us share (x=6, y=Y6_real) for 5-of-6 SSSS over GF(p),
p = 2**521 - 1 (13th Mersenne prime). The 4 teammate shares at x=2..5
have unknown Y2..Y5. The combined secret at x=0 is:

    S = 15*Y2 - 40*Y3 + 45*Y4 - 24*Y5 + 5*Y6   (mod p)

(Lagrange coefficients at x=0 for the point set {2,3,4,5,6}.)

Let K = 15*Y2 - 40*Y3 + 45*Y4 - 24*Y5 (unknown but fixed). So
    combined = K + 5*Y6_submitted

Round 1 (disrupt): submit Y6 = 0. Server reveals combined_1 = K. Done.

Round 2 (target the 1k wallet): compute Y6 = (TARGET - K) * inv(5) mod p.
Submit, server happily returns TARGET as the combined "secret".

Once we know K, we can compute the REAL privkey locally:
    real_priv = K + 5*Y6_real   (mod p)

The flag is hiding in the real privkey somewhere (or the server returns
it after we fool the teammates — we'll print both).
"""
import json
import re
import socket
import time

HOST = "socket.cryptohack.org"
PORT = 13384
P = 2**521 - 1  # 13th Mersenne prime
TARGET_HEX = "8b09cfc4696b91a1cc43372ac66ca36556a41499b495f28cc7ab193e32eadd30"
TARGET = int(TARGET_HEX, 16)


def recv_all(sock, max_wait=3.0):
    sock.settimeout(max_wait)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
            sock.settimeout(0.5)
    except socket.timeout:
        pass
    finally:
        sock.settimeout(max_wait)
    return buf.decode(errors="replace")


def parse_json_lines(blob):
    out = []
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def main():
    sock = socket.create_connection((HOST, PORT))
    greeting = recv_all(sock, 2.0)
    print("-- round 0 --")
    print(greeting)
    parsed = parse_json_lines(greeting)
    share = next(p for p in parsed if p.get("sender") == "your_share")
    Y6_real = int(share["y"], 16)
    print(f"[*] Y6_real = {hex(Y6_real)}")

    # === Round 1: submit fake share y=0, learn K ===
    sock.send(json.dumps({"x": 6, "y": "0x0"}).encode() + b"\n")
    time.sleep(0.8)
    r1 = recv_all(sock, 2.0)
    print("-- round 1 response --")
    print(r1)
    combined1 = None
    for p in parse_json_lines(r1):
        if p.get("sender") == "ssss-combine":
            combined1 = int(p["privkey"], 16)
    assert combined1 is not None, "no combine in round 1"
    K = combined1 % P  # since 5*0 = 0
    print(f"[+] recovered K = {hex(K)}")

    # === Locally compute real privkey ===
    real_priv = (K + 5 * Y6_real) % P
    print(f"[+] REAL privkey = {hex(real_priv)}")

    # === Round 2: target 1k wallet privkey ===
    inv5 = pow(5, -1, P)
    Y6_sub2 = ((TARGET - K) * inv5) % P
    sock.send(json.dumps({"x": 6, "y": hex(Y6_sub2)}).encode() + b"\n")
    time.sleep(0.8)
    r2 = recv_all(sock, 3.0)
    print("-- round 2 response --")
    print(r2)

    # Wait for wallet prompt
    time.sleep(0.5)
    more = recv_all(sock, 2.0)
    if more:
        print("-- more --")
        print(more)

    # === Final: unlock the real wallet ===
    real_hex = f"{real_priv:064x}"
    # Try trimming leading zeros if needed; the server likely just hex-decodes
    sock.send(json.dumps({"privkey": real_hex}).encode() + b"\n")
    time.sleep(0.8)
    final = recv_all(sock, 3.0)
    print("-- wallet response --")
    print(final)

    sock.close()

    print()
    print(f"[*] 1k wallet targeted: {TARGET_HEX}")
    print(f"[*] REAL combined privkey = {hex(real_priv)}")


if __name__ == "__main__":
    main()
