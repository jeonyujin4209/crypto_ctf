"""
Trust Games (Misc / PRNGs) — POC solver

Server (13396.py) keeps a single LCG with 48-bit state and parameters
    a = 0x1337deadbeef,  b = 0xb,  m = 2^48
The LCG is "refreshed" (state ← bytes_to_long(urandom(6))) every 16
get_random_bits calls; each call returns the *top byte* of the new state.

The challenge is to encrypt the server's plaintext with the server's secret
key under AES-CBC. Plaintext and IV are sent to us, key is hidden.

Tracking the LCG call sequence carefully:

  __init__:
    pt_init  : 16 calls — states 1..16 of seed_0
    key_init : 16 calls — states 1..16 of seed_1
    iv_init  : 16 calls — states 1..16 of seed_2
    player   :  8 calls — states 1..8  of seed_3   (counter ends at 8)

  before_input embeds player.hex(), so we *see* the top bytes of seed_3
  states 1..8.

  get_a_challenge():
    plaintext: 16 calls
        first 8: states 9..16 of seed_3
        last  8: states 1..8  of seed_4 (refresh after the 8th)
    key      : 16 calls
        first 8: states 9..16 of seed_4
        last  8: states 1..8  of seed_5
    IV       : 16 calls
        first 8: states 9..16 of seed_5
        last  8: states 1..8  of seed_6

  We get pt and IV in the response, but not key. So:

      key[0..7]  = top bytes of seed_4 states 9..16
      key[8..15] = top bytes of seed_5 states 1..8

How to recover them
-------------------
* From plaintext[8..15] we have top bytes of seed_4 states 1..8 → use Z3 to
  recover seed_4's pre-state (state 0), then step forward to states 9..16.
* From IV[0..7] we have top bytes of seed_5 states 9..16 → recover the state
  right *before* the first observation, which is seed_5's state 8 (= the
  state before output 9). Step *backward* with the LCG inverse to get state 0
  of seed_5, then forward to states 1..8.

The truncated-LCG recovery is just an SMT problem on bit-vectors of width 48
with 8 top-byte equality constraints — Z3 solves it in milliseconds and the
40-bit unknown is over-determined by 8 × 8 = 64 known bits.

Same script, different HOST, against the real server retrieves the real flag.
"""

from __future__ import annotations

import json
import re
import socket
import sys
from pathlib import Path

from Crypto.Cipher import AES

# Use our pure-Python truncated-LCG attack from tools/
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools"))
from trunc_lcg import recover_truncated_lcg_seed  # noqa: E402

HOST = "socket.cryptohack.org"
PORT = 13396
TIMEOUT = 30

A_LCG = 0x1337DEADBEEF
B_LCG = 0xB
M_LCG = 1 << 48
A_INV = pow(A_LCG, -1, M_LCG)


def lcg_step(s: int) -> int:
    return (A_LCG * s + B_LCG) % M_LCG


def lcg_inv(s: int) -> int:
    return (A_INV * (s - B_LCG)) % M_LCG


def recover_pre_state(top_bytes: bytes) -> int:
    """
    Given the top bytes of LCG states (state_1, state_2, ..., state_n) where
    state_{i+1} = a*state_i + b mod m, return state_0 (the state before the
    very first observation).
    """
    seed = recover_truncated_lcg_seed(A_LCG, B_LCG, M_LCG, list(top_bytes), out_bits=8)
    if seed is None:
        raise RuntimeError("truncated LCG attack failed to recover seed")
    return seed


def step_forward(state: int, n: int) -> list[int]:
    """Return [state_1, state_2, ..., state_n] from state_0."""
    out = []
    s = state
    for _ in range(n):
        s = lcg_step(s)
        out.append(s)
    return out


def step_backward(state: int, n: int) -> int:
    """Step the LCG backward n times."""
    s = state
    for _ in range(n):
        s = lcg_inv(s)
    return s


def open_session():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    return sock, f


def main() -> None:
    sock, f = open_session()
    try:
        greeting = f.readline().decode()
        m = re.search(r"Player ([0-9a-f]+)", greeting)
        assert m, f"could not find Player hex in greeting: {greeting!r}"
        player_hex = m.group(1)
        player = bytes.fromhex(player_hex)
        assert len(player) == 8
        print(f"[+] player bytes (seed_3 states 1..8 top): {player.hex()}")

        # Sanity check: recover seed_3 from player and verify with the next 8 bytes.
        seed3_state0 = recover_pre_state(player)
        print(f"[+] recovered seed_3's state_0: {seed3_state0:012x}")

        # Ask for a challenge
        f.write((json.dumps({"option": "get_a_challenge"}) + "\n").encode())
        line = f.readline()
        resp = json.loads(line.decode())
        plaintext = bytes.fromhex(resp["plaintext"])
        IV = bytes.fromhex(resp["IV"])
        print(f"[+] plaintext = {plaintext.hex()}")
        print(f"[+] IV        = {IV.hex()}")
        assert len(plaintext) == 16 and len(IV) == 16

        # Verify recovery: plaintext[0..7] should match top bytes of seed_3 states 9..16
        seed3_states_9_16 = step_forward(seed3_state0, 16)[8:]
        predicted_pt_first = bytes((s >> 40) & 0xFF for s in seed3_states_9_16)
        assert predicted_pt_first == plaintext[:8], (
            f"seed_3 verification failed: got {predicted_pt_first.hex()},"
            f" expected {plaintext[:8].hex()}"
        )
        print("[+] seed_3 recovery verified against plaintext[:8]")

        # Recover seed_4 from plaintext[8..15]
        seed4_state0 = recover_pre_state(plaintext[8:16])
        print(f"[+] recovered seed_4's state_0: {seed4_state0:012x}")
        seed4_states_9_16 = step_forward(seed4_state0, 16)[8:]
        key_first8 = bytes((s >> 40) & 0xFF for s in seed4_states_9_16)
        print(f"[+] key[0..7]  = {key_first8.hex()}")

        # Recover seed_5: IV[0..7] are top bytes of states 9..16, so the
        # recovered "pre-state" is state_8 of seed_5.
        seed5_state8 = recover_pre_state(IV[0:8])
        seed5_state0 = step_backward(seed5_state8, 8)
        print(f"[+] recovered seed_5's state_0: {seed5_state0:012x}")
        seed5_states_1_8 = step_forward(seed5_state0, 8)
        key_last8 = bytes((s >> 40) & 0xFF for s in seed5_states_1_8)
        print(f"[+] key[8..15] = {key_last8.hex()}")

        key = key_first8 + key_last8
        print(f"[+] full key  = {key.hex()}")

        # Compute the expected ciphertext and submit
        ct = AES.new(key, AES.MODE_CBC, IV).encrypt(plaintext)
        print(f"[+] ciphertext = {ct.hex()}")

        f.write((json.dumps({"option": "validate", "ciphertext": ct.hex()}) + "\n").encode())
        line = f.readline()
        resp = json.loads(line.decode())
        print(f"[+] server reply: {resp}")
        msg = resp.get("msg", "")
        m = re.search(r"flag:\s*(crypto\{[^}]*\})", msg)
        if m:
            print()
            print("FLAG:", m.group(1))
        else:
            print("forge failed", file=sys.stderr)
            sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
