#!/usr/bin/env python3
"""
Signing Server - CryptoHack RSA Signatures
Attack: Ask server to sign the encrypted secret directly.
  c = secret^e mod N  (from get_secret)
  sign(c) = c^d mod N = (secret^e)^d mod N = secret
"""

from pwn import *
import json

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13374

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    # strip non-JSON prefix
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def solve():
    if USE_LOCAL:
        r = process(["python3", "13374_fff7c798c8d0c351fd2d05aad6b9d9f0.py"])
    else:
        r = remote(HOST, PORT)

    # Read banner
    r.recvline()

    # Step 1: get public key
    resp = exchange(r, {"option": "get_pubkey"})
    N = int(resp["N"], 16)
    e = int(resp["e"], 16)
    log.info(f"N = {N}")
    log.info(f"e = {e}")

    # Step 2: get encrypted secret  c = secret^e mod N
    resp = exchange(r, {"option": "get_secret"})
    c = int(resp["secret"], 16)
    log.info(f"c = {c}")

    # Step 3: sign(c) = c^d mod N = secret
    resp = exchange(r, {"option": "sign", "msg": hex(c)})
    secret = int(resp["signature"], 16)

    from Crypto.Util.number import long_to_bytes
    flag = long_to_bytes(secret)
    print(f"Flag: {flag.decode()}")

    r.close()

if __name__ == "__main__":
    solve()
