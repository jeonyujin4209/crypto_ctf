"""
Gotta Go Fast (40pts) — One Time Pad / time-based key

Every encrypt() call derives a "one-time pad" from the current UNIX second:

    key = sha256(long_to_bytes(int(time.time()))).digest()

We call get_flag, record our host's current time at that moment, and then
brute-force the server's likely timestamp in a ~60-second window around
our local time (accounting for clock skew and network RTT). For each
candidate t, compute key = sha256(long_to_bytes(t)).digest(), XOR it into
the ciphertext, and check whether the result starts with b"crypto{".
"""
import hashlib
import json
import socket
import time

from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13372
TIMEOUT = 10


def recv_all(sock, max_wait=3.0):
    sock.settimeout(0.5)
    data = b""
    end = time.time() + max_wait
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            end = time.time() + 0.4
        except socket.timeout:
            if data:
                break
    return data.decode("utf-8", errors="replace")


def main():
    sock = socket.create_connection((HOST, PORT))
    recv_all(sock, 1.5)  # greeting

    t_now = int(time.time())
    sock.send((json.dumps({"option": "get_flag"}) + "\n").encode())
    reply = recv_all(sock, 3.0)
    sock.close()

    import re
    m = re.search(r'"encrypted_flag":\s*"([0-9a-f]+)"', reply)
    assert m, f"no encrypted_flag in {reply!r}"
    ct = bytes.fromhex(m.group(1))
    print(f"[*] cipher = {ct.hex()}  ({len(ct)} bytes)")

    # Brute-force timestamps in [t_now - 30, t_now + 30]
    for delta in range(-30, 31):
        t = t_now + delta
        key = hashlib.sha256(long_to_bytes(t)).digest()
        pt = bytes(c ^ k for c, k in zip(ct, key))
        if pt.startswith(b"crypto{"):
            print(f"[+] t = {t} (delta = {delta:+d})")
            print(f"FLAG: {pt.decode(errors='replace')}")
            return
    print("[!] no match in window — widen range")


if __name__ == "__main__":
    main()
