"""
Couples (50pts) — BLS verifier bypass via z = 0

The server multiplies both pairing inputs by (x*z). If we can make z=0,
then xzH and xzG are the identity, and both pairings equal 1 regardless
of the "hsh" and "G" we submit.

set_internal_z replaces self.z with inverse(poly(new_z, x), p) where
    poly(new_z, x) = x^(new_z+7) - x^3  (mod p).
Picking new_z = p - 5:
    poly = x^(p+2) - x^3 = x^(p-1)*x^3 - x^3 = 1*x^3 - x^3 = 0   (Fermat)
so inverse(0, p) returns 0 (via the server's extended-gcd), and z = 0.

The guard `if (x*z)%p == 1: raise` accepts z=0 (0 != 1). Then:
    xzH = multiply(xH, 0) = identity
    xzG = multiply(xG, 0) = identity
    pairing(identity, *) == 1, so l == r == 1 — BLS verifier passes.

For the do_proof we submit G = G1 (valid curve point) and any hsh.
"""
import json
import socket
import time

HOST = "socket.cryptohack.org"
PORT = 13415

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583


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


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def main():
    sock = socket.create_connection((HOST, PORT))
    time.sleep(0.5)
    print(recv_all(sock, 1.0).strip())

    # Step 1: set z so that poly(new_z, x) == 0 (mod p)
    new_z = p - 5  # x^(new_z+7) - x^3 = x^(p+2)-x^3 = x^3-x^3 = 0 (Fermat)
    send_json(sock, {"option": "set_internal_z", "z": hex(new_z)})
    time.sleep(0.4)
    print(recv_all(sock, 1.0).strip())

    # Step 2: submit any G on curve (use G1) and any hsh — pairings are both 1.
    G1_str = "(1, 2, 1)"  # py_ecc's G1 in optimized form: (x=1, y=2, z=1)
    send_json(sock, {"option": "do_proof", "G": G1_str, "hsh": hex(1)})
    time.sleep(0.5)
    print(recv_all(sock, 2.0).strip())
    sock.close()


if __name__ == "__main__":
    main()
