"""
Too Honest (30pts) — unrange-checked challenge e + unreduced z

The server computes z = r + e*w (over Z, NOT modulo q) and never checks
that e is in [0, 2^128). So we can send an arbitrarily large e:
    e = 2^1000  (>> r_max = 2^768)
    z = r + e*w
    z // e = floor(r/e) + w = 0 + w = w   (since r < e)
which directly recovers the flag integer w.
"""
import json
import socket
import time
from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13429


def recv_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    return buf.decode()


def parse_json_lines(blob):
    out = []
    for line in blob.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def main():
    sock = socket.create_connection((HOST, PORT))
    time.sleep(0.8)
    blob = recv_all(sock, 2.0)
    print("-- challenge --")
    print(blob)

    e = 1 << 1000
    sock.send((json.dumps({"e": e}) + "\n").encode())
    time.sleep(0.8)
    resp = recv_all(sock, 2.0)
    print("-- prove --")
    print(resp[:200], "...")

    parsed = parse_json_lines(resp)
    z = parsed[0]["z"]
    w = z // e
    flag_bytes = long_to_bytes(w)
    print(f"[+] w = {hex(w)}")
    print(f"[+] bytes = {flag_bytes}")
    sock.close()


if __name__ == "__main__":
    main()
