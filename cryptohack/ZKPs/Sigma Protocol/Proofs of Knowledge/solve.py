"""
Proofs of Knowledge (10pts) — Schnorr identification

Classic Schnorr protocol. w is hardcoded in the challenge source, so
we just run the honest prover:
    1. pick r in [0, q), send a = g^r mod p
    2. receive e
    3. send z = r + e*w mod q
"""
import json
import random
import socket

HOST = "socket.cryptohack.org"
PORT = 13425

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5


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
    greeting = recv_line(sock)
    print(f"[*] greeting: {greeting.strip()}")

    r = random.randint(0, q - 1)
    a = pow(g, r, p)
    send_json(sock, {"a": a})
    resp = json.loads(recv_line(sock))
    print(f"[1] {resp}")
    e = resp["e"] if isinstance(resp["e"], int) else int(resp["e"], 0)
    z = (r + e * w) % q
    send_json(sock, {"z": z})
    final = json.loads(recv_line(sock))
    print(f"[+] {final}")
    sock.close()


if __name__ == "__main__":
    main()
