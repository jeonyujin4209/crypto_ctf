"""
ProSign 3 (100pts) — EC / Signatures

The bug is in `sign_time`:

    def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        ...                                # ↑ shadows the outer `n`!
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))

The local `n` (the seconds field) shadows the outer `n` (curve order).
The nonce `randrange(1, n)` therefore produces a value in [1, seconds),
which is **at most 59**. With such a tiny nonce, brute-forcing all 60
possible k values recovers the secret d directly:

    s ≡ k⁻¹ (h + r·d)        ⇒        d ≡ (s·k - h) · r⁻¹  (mod n)

Once we know d, we can sign "unlock" with a fresh (proper) nonce and
submit it to the verify endpoint to receive the flag.

Server: socket.cryptohack.org 13381
"""
import hashlib
import json
import socket
import time

from ecdsa.ecdsa import generator_192, Public_key, Private_key, Signature
from ecdsa.numbertheory import inverse_mod

HOST = "socket.cryptohack.org"
PORT = 13381

g = generator_192
n = g.order()


def recv_json(sock, max_wait=3.0):
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


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())
    return recv_json(sock, 3.0)


def parse_jsons(text):
    out, depth, start = [], 0, None
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    out.append(json.loads(text[start : i + 1]))
                except json.JSONDecodeError:
                    pass
                start = None
    return out


def main():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(15)
    recv_json(sock, 1.5)  # greeting

    print("[1] sign_time()")
    reply = send_json(sock, {"option": "sign_time"})
    print("    ", reply.strip())
    js = parse_jsons(reply)
    sig_data = next(j for j in js if "msg" in j)
    msg = sig_data["msg"]
    r = int(sig_data["r"], 16)
    s = int(sig_data["s"], 16)

    h = int.from_bytes(hashlib.sha1(msg.encode()).digest(), "big")
    print(f"    msg = {msg!r}")
    print(f"    r = {hex(r)[:20]}...")
    print(f"    s = {hex(s)[:20]}...")

    # Brute-force k in [1, 60)
    print("[2] brute-forcing tiny nonce k ∈ [1, 60)")
    r_inv = inverse_mod(r, n)
    candidates = []
    for k in range(1, 60):
        d = ((s * k - h) * r_inv) % n
        # Verify by checking k*G has the right x = r
        Q = k * g
        if Q.x() == r:
            print(f"    k = {k}, d = {d}")
            candidates.append(d)

    if not candidates:
        raise RuntimeError("no nonce candidate matched")

    # Each k that satisfies (k·G).x == r gives a valid d. Try each.
    for d in candidates:
        print(f"[3] trying d = {d}")
        # Forge a signature for "unlock"
        pub = Public_key(g, g * d)
        priv = Private_key(pub, d)
        h_unlock = int.from_bytes(hashlib.sha1(b"unlock").digest(), "big")
        sig = priv.sign(h_unlock, 0xC0FFEE)  # any non-trivial nonce

        reply = send_json(sock, {
            "option": "verify",
            "msg": "unlock",
            "r": hex(sig.r),
            "s": hex(sig.s),
        })
        print("    ", reply.strip())
        if "flag" in reply.lower():
            break
    sock.close()


if __name__ == "__main__":
    main()
