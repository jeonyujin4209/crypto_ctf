#!/usr/bin/env python3
"""
Vote for Pedro - CryptoHack RSA Signatures
Attack: Bleichenbacher low-exponent signature forgery (e=3).

The server does:
  verified_vote = long_to_bytes(pow(vote, 3, ALICE_N))
  vote_msg = verified_vote.split(b'\\x00')[-1]
  check if vote_msg == b'VOTE FOR PEDRO'

We need vote^3 mod N where the byte representation ends with \\x00VOTE FOR PEDRO.
Since N is 2048-bit and e=3, if vote < N^(1/3), no modular reduction happens.

Strategy: Use Hensel lifting to find x such that x^3 mod 2^120 has the
right low 15 bytes, then set high bits so x^3 < N.
"""

from pwn import *
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13375

ALICE_N = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
ALICE_E = 3

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def solve():
    target_msg = b'VOTE FOR PEDRO'
    suffix_int = bytes_to_long(b'\x00' + target_msg)  # 15 bytes
    nbytes = 15
    nbits = nbytes * 8  # 120

    # Hensel lifting: find x such that x^3 = suffix_int mod 2^120
    x = suffix_int % 2
    for k in range(2, nbits + 1):
        mod = 1 << k
        if pow(x, 3, mod) != suffix_int % mod:
            x = x + (1 << (k - 1))
        assert pow(x, 3, mod) == suffix_int % mod

    # Set high bits: x_full = x + t * 2^120, pick t so x_full^3 < N
    t = 1 << 200
    vote = x + t * (1 << nbits)

    # Verify locally
    cube = vote ** 3
    assert cube < ALICE_N, "vote^3 must be < N"
    cube_bytes = long_to_bytes(cube)
    last_seg = cube_bytes.split(b'\x00')[-1]
    assert last_seg == target_msg, f"Mismatch: {last_seg}"
    log.success("Local verification passed")

    # Connect and submit
    if USE_LOCAL:
        r = process(["python3", "13375_7eaca879f3911da349a7248f302c6344.py"])
    else:
        r = remote(HOST, PORT)

    r.recvline()  # banner

    resp = exchange(r, {"option": "vote", "vote": hex(vote)})
    print(f"Response: {resp}")

    r.close()

if __name__ == "__main__":
    solve()
