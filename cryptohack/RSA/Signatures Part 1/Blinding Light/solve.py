#!/usr/bin/env python3
"""
Blinding Light - CryptoHack RSA Signatures
Attack: RSA blinding to forge admin signature.
  1. Get public key (N, e)
  2. Choose random r, compute blinded = (r^e * admin_int) mod N
  3. Server signs blinded (it doesn't contain "admin=True" as bytes)
  4. Recover real signature: sig = blinded_sig * r^(-1) mod N
  5. Submit (admin=True, sig) to verify
"""

from pwn import *
import json
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13376

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def solve():
    if USE_LOCAL:
        r = process(["python3", "13376_43ed0ce3200294aa8cd3a797abd12fc9.py"])
    else:
        r = remote(HOST, PORT)

    r.recvline()  # banner

    # Step 1: get public key
    resp = exchange(r, {"option": "get_pubkey"})
    N = int(resp["N"], 16)
    e = int(resp["e"], 16)
    log.info(f"N = {N}")
    log.info(f"e = {e}")

    # Step 2: RSA blinding
    admin_msg = b"admin=True"
    m = bytes_to_long(admin_msg)

    # Choose random blinding factor
    r_blind = random.randint(2, N - 1)
    # Compute blinded message: (r^e * m) mod N
    blinded = (pow(r_blind, e, N) * m) % N

    # Send blinded message for signing (as hex bytes)
    blinded_hex = long_to_bytes(blinded).hex()
    resp = exchange(r, {"option": "sign", "msg": blinded_hex})
    blinded_sig = int(resp["signature"], 16)

    # Step 3: Unblind: real_sig = blinded_sig * r^(-1) mod N
    r_inv = pow(r_blind, -1, N)
    real_sig = (blinded_sig * r_inv) % N

    # Step 4: Verify with admin=True
    resp = exchange(r, {
        "option": "verify",
        "msg": admin_msg.hex(),
        "signature": hex(real_sig)
    })
    print(f"Response: {resp}")

    r.close()

if __name__ == "__main__":
    solve()
