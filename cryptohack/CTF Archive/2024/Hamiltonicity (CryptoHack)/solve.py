"""
Hamiltonicity (CryptoHack) — Online Fiat-Shamir grinding

Vulnerability:
    The challenge implements a Hamiltonicity ZKP via Fiat-Shamir, but the
    challenge bit for round i is computed ONLINE from only A_i and the
    previous FS state:
        FS_state_i = hash(comm_params, FS_state_{i-1}, A_i)
        challenge_i = FS_state_i[-1] & 1
    Because we control A_i (random Pedersen commitments to a permuted graph),
    we can simply re-roll A_i with fresh randomness until challenge_i = 0.
    For challenge=0 we only need to reveal the permutation + open the entire
    matrix, which we can always do (no Hamilton cycle needed).

Attack:
    For each of 128 rounds, repeatedly commit to a randomly permuted version
    of G with fresh r values. Hash and check the resulting challenge bit. If
    it is 0, send (permutation, full openings). Roughly 2 attempts per round.

Skill: skills/attack/hamiltonicity-online-fs-grinding.md
"""

import json
import random
import sys
import os

# import challenge utilities
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hamiltonicity import (
    commit_to_graph,
    permute_graph,
    hash_committed_graph,
    comm_params,
)
from pwn import remote

HOST = "archive.cryptohack.org"
PORT = 14635
NUMROUNDS = 128

# Graph with no Hamiltonian cycle (from chal.py, LocalTest=False)
N = 5
G = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0],
]


def grind_round(FS_state):
    """Find an A and openings such that challenge bit = 0."""
    while True:
        permutation = list(range(N))
        random.shuffle(permutation)
        G_perm = permute_graph(G, N, permutation)
        A, openings = commit_to_graph(G_perm, N)
        trial_state = hash_committed_graph(A, FS_state, comm_params)
        if (trial_state[-1] & 1) == 0:
            return A, openings, permutation, trial_state


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"prove to me that G has a hamiltonian cycle!")

    FS_state = b""
    for i in range(NUMROUNDS):
        A, openings, permutation, trial_state = grind_round(FS_state)
        FS_state = trial_state
        # challenge=0 response: reveal permutation + entire matrix openings
        z = [permutation, openings]
        payload = {"A": A, "z": z}
        io.recvuntil(b"send fiat shamir proof: ")
        io.sendline(json.dumps(payload).encode())
        resp = io.recvline()
        if i % 16 == 0 or i == NUMROUNDS - 1:
            print(f"round {i}: {resp.strip().decode(errors='replace')}")
        if b"didn't verify" in resp:
            print("verification failed!")
            io.close()
            return

    # collect remainder
    rest = io.recvall(timeout=5)
    print(rest.decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    main()
