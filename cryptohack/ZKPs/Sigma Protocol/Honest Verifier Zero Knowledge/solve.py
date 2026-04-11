"""
Honest Verifier Zero Knowledge (20pts) — Schnorr simulator

Server gives us the challenge e FIRST, then expects (a, z) such that
    g^z == a * y^e  (mod p)
This is exactly the Schnorr simulator: pick random z, let
    a := g^z * y^(-e)   (mod p)
No knowledge of the witness w needed.
"""
import json
import random
import socket

HOST = "socket.cryptohack.org"
PORT = 13427

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2


def recv_line(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(4096)
        if not c:
            break
        buf += c
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def main():
    sock = socket.create_connection((HOST, PORT))
    # Server has no_prompt=True, so on connect it sends BOTH the greeting
    # line AND the initial CHALLENGE-state response in one burst.
    import time
    time.sleep(0.8)
    sock.settimeout(2.0)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    blob = buf.decode()
    # Find the JSON line
    json_line = next(l for l in blob.splitlines() if l.startswith("{"))
    resp = json.loads(json_line)
    e = resp["e"]
    y = resp["y"]
    print(f"[*] e={e}")

    z = random.randint(1, q - 1)
    y_inv_e = pow(pow(y, e, p), -1, p)
    a = (pow(g, z, p) * y_inv_e) % p

    # sanity check: g^z should equal a * y^e mod p
    assert pow(g, z, p) == (a * pow(y, e, p)) % p
    assert pow(a, q, p) == 1
    payload = {"a": a, "z": z}
    raw_send = json.dumps(payload) + "\n"
    print(f"[DBG] sending: {raw_send[:80]}... len={len(raw_send)}")
    sock.send(raw_send.encode())
    raw = recv_line(sock)
    print(f"[DBG] raw response: {raw!r}")
    final = json.loads(raw)
    print(f"[+] {final}")
    sock.close()


if __name__ == "__main__":
    main()
