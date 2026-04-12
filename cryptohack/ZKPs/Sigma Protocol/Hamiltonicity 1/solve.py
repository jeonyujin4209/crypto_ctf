"""
Hamiltonicity 1 - CTF Archive Challenge
archive.cryptohack.org:14635

The graph G has NO Hamiltonian cycle. We need to convince the server it does.

The Fiat-Shamir vulnerability:
- For each round i, the server computes: FS_state = hash(comm_params || prev_state || A_i)
- challenge_i = FS_state[-1] & 1

Since challenges are computed ONLINE (one per round, using the running FS state),
we can adaptively choose A_i to get challenge=0 every time!

When challenge=0: we just need to open all commitments and show A is a permutation of G
=> We can always do this without knowing a Hamiltonian cycle!

When challenge=1: we need to open a Hamiltonian cycle
=> We can't do this (no cycle exists in G)

Attack: For each round, try different random permutations of G until hash[-1] & 1 == 0.
"""

import socket
import random
import json
from hashlib import sha256

# Pedersen commitment parameters (from hamiltonicity.py)
P = 0x19dad539e2d348cc3ab07d51f2bb6491d1552aa8cf1db928920fd3d86946aed8805d2e279fa8632dd5fbab8aaf7df1069906b057cc785b7f191ef1b9b5da38cff2e7c64da17bb56a058707d9fd69e546a95e502e556a314c587c7ae36c3d1122e6954f5d81dd9239e02f61b045360187b4caeed271cec1919a0d8a39e855040cf
q_ped = 0xced6a9cf169a4661d583ea8f95db248e8aa9554678edc944907e9ec34a3576c402e9713cfd43196eafdd5c557bef8834c83582be63c2dbf8c8f78dcdaed1c67f973e326d0bddab502c383ecfeb4f2a354af28172ab518a62c3e3d71b61e8891734aa7aec0eec91cf017b0d8229b00c3da65776938e760c8cd06c51cf42a82067
h1 = 250335104192448110684442096964171969189371208477846978499544515755228857598805930673171509152681305793789903169450438090936970626429806187630240086681623358732517929314870247393468568111513100989768455673769015138136779312483203922847547169463972757664497001482465636402329003817055202840451714256443734563502
h2 = 50837518481371967588098771977165879422445597094015682347125264774697010574110399136037637691883034517374621248070926110725252171239208140392324019115211573768989274797050961703999139947885402838647962534519882622024973824201026885393782961783980351898031905383197219266093119145616328556294476943229578292306
comm_params = P, q_ped, h1, h2

# The graph G with NO Hamiltonian cycle
N = 5
G = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0]
]

HOST = 'archive.cryptohack.org'
PORT = 14635


def pedersen_commit(message):
    r = random.randint(0, q_ped)
    commitment = (pow(h1, message, P) * pow(h2, r, P)) % P
    return commitment, r


def pedersen_open(commitment, message, r):
    if (commitment * pow(h1, -message, P) * pow(h2, -r, P)) % P == 1:
        return True
    return False


def commit_to_graph(G, N):
    G2 = [[0] * N for _ in range(N)]
    openings = [[0] * N for _ in range(N)]
    for i in range(N):
        for j in range(N):
            v = G[i][j]
            comm, r = pedersen_commit(v)
            G2[i][j] = comm
            openings[i][j] = [v, r]
    return G2, openings


def permute_graph(G, N, permutation):
    return [[G[permutation[i]][permutation[j]] for j in range(N)] for i in range(N)]


def hash_committed_graph(A, state, comm_params_val):
    fs_state = sha256(str(comm_params_val).encode())
    fs_state.update(state)
    first_message = "".join([str(x) for xs in A for x in xs])
    fs_state.update(first_message.encode())
    return fs_state.digest()


class Connection:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(60)
        self.s.connect((HOST, PORT))
        self.buf = b''

    def recv_until(self, marker):
        if isinstance(marker, str):
            marker = marker.encode()
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Exception("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result

    def recv_line(self):
        return self.recv_until(b'\n').decode().strip()

    def send_json(self, obj):
        data = json.dumps(obj).encode() + b'\n'
        self.s.sendall(data)


def main():
    print("[*] Connecting to Hamiltonicity 1...")
    conn = Connection()

    # Read initial message
    msg = conn.recv_until(b"prove to me that G has a hamiltonian cycle!\n")
    print(f"  Server: prove to me that G has a hamiltonian cycle!")

    numrounds = 128
    FS_state = b''

    for i in range(numrounds):
        print(f"[*] Round {i + 1}/{numrounds}")

        # We want challenge = 0, so we can just open the permutation
        # Try different permutations until we get a challenge bit of 0
        attempts = 0
        while True:
            attempts += 1
            # Create a permutation and commit to the permuted G
            permutation = list(range(N))
            random.shuffle(permutation)

            # Commit to the permuted graph
            G_permuted = permute_graph(G, N, permutation)
            A, openings = commit_to_graph(G_permuted, N)

            # Compute what the challenge would be
            trial_state = hash_committed_graph(A, FS_state, comm_params)
            challenge = trial_state[-1] & 1

            if challenge == 0:
                # We can answer this challenge!
                break

            if attempts > 1000:
                print(f"[!] Too many attempts, trying identity permutation")
                # Just use identity and hope
                permutation = list(range(N))
                G_permuted = permute_graph(G, N, permutation)
                A, openings = commit_to_graph(G_permuted, N)
                trial_state = hash_committed_graph(A, FS_state, comm_params)
                break

        # Update FS state
        FS_state = trial_state
        challenge = FS_state[-1] & 1

        print(f"  challenge={challenge}, attempts={attempts}")

        # Build the response
        if challenge == 0:
            # Open all commitments and show permutation
            # Need openings = [[v, r] for each cell] structured properly
            # z = [permutation, openings_of_everything]
            # But we need openings for the permuted graph A (which IS our committed graph)
            # A = permuted G with commitments
            # We need openings to open A back to permuted G
            # Then G_test = permute_graph(G, N, permutation)
            # They check if open_graph(A) == G_test
            #
            # A was committed as G_permuted = permute_graph(G, N, permutation)
            # So openings already contain the right values
            z = [permutation, openings]
        else:
            # challenge=1 - we need a Hamiltonian cycle in A
            # This should not happen given our strategy
            print("[!] Got challenge=1, this shouldn't happen!")
            # Create a fake cycle (this will likely fail)
            fake_cycle = [[i, (i + 1) % N] for i in range(N)]
            fake_openings = [openings[i][(i + 1) % N][1] for i in range(N)]
            z = [fake_cycle, fake_openings]

        # Send the proof
        prompt = conn.recv_until(b"send fiat shamir proof: ")
        conn.send_json({"A": A, "z": z})

        # Read response
        resp = conn.recv_line()
        print(f"  Server: {resp}")
        if b"didn't verify" in resp.encode() or "didn't verify" in resp:
            print("[!] Server rejected proof!")
            return

    # Read final messages
    try:
        while True:
            line = conn.recv_line()
            if line:
                print(f"  {line}")
            if 'crypto{' in line:
                print(f"\n[+] FLAG: {line}")
                break
    except:
        pass


if __name__ == '__main__':
    main()
