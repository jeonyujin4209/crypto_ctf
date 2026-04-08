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
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

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

def emsa_pkcs1_v15_encode(msg_bytes, emLen):
    """EMSA-PKCS1-v1.5 encoding for SHA-256"""
    # DER encoding of DigestInfo for SHA-256
    der_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    h = hashlib.sha256(msg_bytes).digest()
    T = der_prefix + h

    if emLen < len(T) + 11:
        raise ValueError("intended encoded message length too short")

    PS = b'\xff' * (emLen - len(T) - 3)
    EM = b'\x00\x01' + PS + b'\x00' + T
    return EM

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

    # Step 3: Compute EMSA-PKCS1-v1.5 digest for our message
    digest = emsa_pkcs1_v15_encode(msg.encode(), 256)
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
