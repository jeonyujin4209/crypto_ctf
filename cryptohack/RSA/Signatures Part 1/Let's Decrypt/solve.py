#!/usr/bin/env python3
"""
Let's Decrypt - CryptoHack RSA Signatures
Attack: We control N and e in verification. Set e=1, then:
  pow(SIGNATURE, 1, N) = SIGNATURE mod N
  We need SIGNATURE mod N = digest_int
  So set N = SIGNATURE - digest_int (assuming SIGNATURE > digest_int)
"""

from pwn import *
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pkcs1 import emsa_pkcs1_v15

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13391

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def solve():
    if USE_LOCAL:
        r = process(["python3", "13391_5bb4e548ed254cef357799685c887460.py"])
    else:
        r = remote(HOST, PORT)

    r.recvline()  # banner

    # Step 1: get the SIGNATURE from server
    resp = exchange(r, {"option": "get_signature"})
    SIGNATURE = int(resp["signature"], 16)
    log.info(f"SIGNATURE = {SIGNATURE}")

    # Step 2: Craft our message matching the regex pattern
    msg = "I am Mallory and I own CryptoHack.org"

    # Step 3: Compute EMSA-PKCS1-v1.5 digest using same library as server
    digest = emsa_pkcs1_v15.encode(msg.encode(), 256)
    digest_int = bytes_to_long(digest)
    log.info(f"digest_int = {digest_int}")

    # Step 4: Set e=1, N = SIGNATURE - digest_int
    # pow(SIGNATURE, 1, N) = SIGNATURE mod N = SIGNATURE - N = digest_int
    N = SIGNATURE - digest_int
    assert N > 0, "SIGNATURE must be > digest_int"
    assert SIGNATURE % N == digest_int, "Verification failed"

    log.info(f"Crafted N = {N}")

    # Step 5: Submit for verification
    resp = exchange(r, {
        "option": "verify",
        "msg": msg,
        "N": hex(N),
        "e": hex(1)
    })
    print(f"Response: {resp}")

    r.close()

if __name__ == "__main__":
    solve()
