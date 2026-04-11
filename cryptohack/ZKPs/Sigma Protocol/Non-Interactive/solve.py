"""
Non-Interactive (20pts) — Fiat-Shamir Schnorr with hardcoded w

w is baked into the challenge source. Run the honest prover using
Fiat-Shamir:
    r = random, a = g^r, e = sha512(str(a).encode()) mod 2^511,
    z = r + e*w mod q
"""
import json
import random
import socket
import time
from hashlib import sha512
from Crypto.Util.number import bytes_to_long

HOST = "socket.cryptohack.org"
PORT = 13428

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w = 0xdb968f9220c879b58b71c0b70d54ef73d31b1627868921dfc25f68b0b9495628b5a0ea35a80d6fd4f2f0e452116e125dc5e44508b1aaec89891dddf9a677ddc0


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


def main():
    sock = socket.create_connection((HOST, PORT))
    time.sleep(0.6)
    blob = recv_all(sock, 2.0)
    print(blob)

    r = random.randint(1, q - 1)
    a = pow(g, r, p)
    fiat_shamir_input = str(a).encode()
    e = bytes_to_long(sha512(fiat_shamir_input).digest()) % 2**511
    z = (r + e * w) % q

    sock.send((json.dumps({"a": a, "z": z}) + "\n").encode())
    time.sleep(0.6)
    resp = recv_all(sock, 2.0)
    print(resp)
    sock.close()


if __name__ == "__main__":
    main()
