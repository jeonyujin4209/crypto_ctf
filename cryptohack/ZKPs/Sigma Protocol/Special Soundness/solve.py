"""
Special Soundness (20pts) — Schnorr nonce reuse

The prover bug: it reuses the same r across two protocol runs. Given two
transcripts (a, e1, z1), (a, e2, z2) with the same commitment a = g^r,
    z1 = r + e1*w  (mod q)
    z2 = r + e2*w  (mod q)
subtract:
    w = (z1 - z2) * (e1 - e2)^{-1}  (mod q)
and w is (bytes_to_long of) the padded flag.
"""
import json
import socket
import time

from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13426
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7


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
    parts = parse_json_lines(blob)
    assert parts, f"no json: {blob!r}"
    r1 = parts[0]
    a1 = r1["a"]
    y = r1["y"]
    print(f"[1] a={a1}")

    e1 = 0xcafebabe  # arbitrary
    sock.send((json.dumps({"e": e1}) + "\n").encode())
    time.sleep(0.8)
    blob = recv_all(sock, 2.0)
    parts = parse_json_lines(blob)
    assert len(parts) >= 2, f"expected 2 json: {blob!r}"
    z1 = parts[0]["z"]
    a2 = parts[1]["a2"]
    print(f"[2] z1={z1}  a2={a2}  (a == a2? {a1 == a2})")

    e2 = 0xdeadbeef
    sock.send((json.dumps({"e": e2}) + "\n").encode())
    time.sleep(0.8)
    blob = recv_all(sock, 2.0)
    parts = parse_json_lines(blob)
    z2 = parts[0]["z2"]
    print(f"[3] z2={z2}")

    w = ((z1 - z2) * pow(e1 - e2, -1, q)) % q
    print(f"[+] w = {hex(w)}")
    raw = long_to_bytes(w)
    print(f"[+] flag bytes: {raw}")

    sock.close()


if __name__ == "__main__":
    main()
