"""
Hash Stuffing (50pts) — Hash Functions / Collisions

Custom CryptoHash with BLOCK_SIZE=32. The keyed mixing looks intimidating
(40 rounds of scramble_block, XOR, rotations, etc.) but every block is
processed deterministically by `scramble_block` and XORed into the state —
so if two distinct messages produce the *same padded byte string*, they
collide trivially.

Look at the padding function:

    def pad(data):
        padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
        return data + bytes([padding_len] * padding_len)

This is **not injective**. Consider:

    a = b'A'                 (len 1)
        → padding_len = (32 - 1) % 32 = 31
        → pad(a) = b'A' + b'\\x1f' * 31          (32 bytes)

    b = b'A' + b'\\x1f' * 31  (len 32)
        → padding_len = (32 - 32) % 32 = 0
        → pad(b) = b                            (same 32 bytes)

`pad(a) == pad(b)` while `a != b`, so `cryptohash(a) == cryptohash(b)`.
No block-level analysis of `scramble_block` needed — classic Merkle-Damgård
MD-strengthening failure (no length encoding, non-injective padding).

Server: socket.cryptohack.org 13405
"""

import json
import socket
import sys
import time

from source import cryptohash, pad

HOST = "socket.cryptohack.org"
PORT = 13405
TIMEOUT = 15


def build_collision():
    a = b"A"
    b = b"A" + b"\x1f" * 31
    assert a != b
    assert pad(a) == pad(b), "pad collision broken"
    assert cryptohash(a) == cryptohash(b), "hash collision broken"
    return a, b


def recv_all(sock, max_wait=2.5):
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
    a, b = build_collision()
    print(f"[+] local collision confirmed")
    print(f"    a = {a.hex()}  (len {len(a)})")
    print(f"    b = {b.hex()}  (len {len(b)})")
    print(f"    hash = {cryptohash(a)}")

    sock = socket.create_connection((HOST, PORT))
    recv_all(sock, 2.0)  # greeting
    payload = json.dumps({"m1": a.hex(), "m2": b.hex()}).encode() + b"\n"
    sock.send(payload)
    reply = recv_all(sock, 3.0)
    sock.close()
    print("[+] server:", reply.strip())


if __name__ == "__main__":
    main()
