"""
Hamiltonicity 2 - CTF Archive Challenge
archive.cryptohack.org:34597

Server protocol:
1. Collects ALL 128 (A, z) pairs first (batch mode)
2. Computes hash chain: FS_state = hash(A_0, b''); FS_state = hash(A_1, FS_state); ...
3. challenge_bits = bin(int.from_bytes(FS_state, 'big'))[-128:]
4. challenge_i = int(challenge_bits[i])
5. Verifies each round with appropriate check

Attack: Fixed-point iteration
- Generate 2 sets of A values per round (type-0: commit to perm(G), type-1: commit to FAKE_G)
- Find assignment (128 bits) such that:
  hash_chain(A_selected_by_assignment)[-128_bits] = assignment
- If iteration doesn't converge after N tries, regenerate fresh A pairs and retry

z format (from source):
- challenge=0: z = [permutation, full_NxN_openings]  where openings[i][j] = [v, r]
- challenge=1: z = [cycle_edges, r_vals]  where r_vals[i] = just the r integer
"""

import socket
import random
import json
from hashlib import sha256

# Pedersen commitment parameters
P = 0x19dad539e2d348cc3ab07d51f2bb6491d1552aa8cf1db928920fd3d86946aed8805d2e279fa8632dd5fbab8aaf7df1069906b057cc785b7f191ef1b9b5da38cff2e7c64da17bb56a058707d9fd69e546a95e502e556a314c587c7ae36c3d1122e6954f5d81dd9239e02f61b045360187b4caeed271cec1919a0d8a39e855040cf
q_ped = 0xced6a9cf169a4661d583ea8f95db248e8aa9554678edc944907e9ec34a3576c402e9713cfd43196eafdd5c557bef8834c83582be63c2dbf8c8f78dcdaed1c67f973e326d0bddab502c383ecfeb4f2a354af28172ab518a62c3e3d71b61e8891734aa7aec0eec91cf017b0d8229b00c3da65776938e760c8cd06c51cf42a82067
h1 = 250335104192448110684442096964171969189371208477846978499544515755228857598805930673171509152681305793789903169450438090936970626429806187630240086681623358732517929314870247393468568111513100989768455673769015138136779312483203922847547169463972757664497001482465636402329003817055202840451714256443734563502
h2 = 50837518481371967588098771977165879422445597094015682347125264774697010574110399136037637691883034517374621248070926110725252171239208140392324019115211573768989274797050961703999139947885402838647962534519882622024973824201026885393782961783980351898031905383197219266093119145616328556294476943229578292306
comm_params = P, q_ped, h1, h2

N = 5
G = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0]
]

# Fake graph: simple 5-cycle 0→1→2→3→4→0
FAKE_CYCLE = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)]
FAKE_G = [[0] * N for _ in range(N)]
for src, dst in FAKE_CYCLE:
    FAKE_G[src][dst] = 1

HOST = 'archive.cryptohack.org'
PORT = 34597


def pedersen_commit(message):
    r = random.randint(0, q_ped)
    commitment = (pow(h1, message, P) * pow(h2, r, P)) % P
    return commitment, r


def commit_to_graph(G_input):
    G2 = [[0] * N for _ in range(N)]
    openings = [[0] * N for _ in range(N)]
    for i in range(N):
        for j in range(N):
            v = G_input[i][j]
            comm, r = pedersen_commit(v)
            G2[i][j] = comm
            openings[i][j] = [v, r]
    return G2, openings


def permute_graph(G_input, perm):
    return [[G_input[perm[i]][perm[j]] for j in range(N)] for i in range(N)]


def hash_committed_graph(A, state):
    fs = sha256(str(comm_params).encode())
    fs.update(state)
    fs.update("".join([str(x) for xs in A for x in xs]).encode())
    return fs.digest()


def gen_proof_for_challenge0():
    """Commit to perm(G); z = [permutation, full_NxN_openings]"""
    perm = list(range(N))
    random.shuffle(perm)
    G_perm = permute_graph(G, perm)
    A, openings = commit_to_graph(G_perm)
    z = [perm, openings]
    return A, z


def gen_proof_for_challenge1():
    """Commit to FAKE_G; z = [cycle_edges, r_vals] where r_vals are just integers"""
    A, openings = commit_to_graph(FAKE_G)
    cycle = [list(e) for e in FAKE_CYCLE]
    r_vals = [openings[src][dst][1] for src, dst in FAKE_CYCLE]
    z = [cycle, r_vals]
    return A, z


def compute_challenges(proofs_for_0, proofs_for_1, assignment):
    """Compute the server's challenge bits for a given assignment."""
    state = b''
    for i in range(128):
        A = proofs_for_0[i][0] if assignment[i] == 0 else proofs_for_1[i][0]
        state = hash_committed_graph(A, state)
    bits = bin(int.from_bytes(state, 'big'))[-128:]
    # Pad left with zeros if needed (in case of short hash)
    bits = bits.zfill(128)
    return [int(bits[i]) for i in range(128)]


def find_fixed_point():
    """Find 128 proofs where challenge bits match proof types (fixed point)."""
    outer_attempt = 0
    while True:
        outer_attempt += 1
        if outer_attempt % 10 == 1:
            print(f"[*] Generating fresh A pairs (attempt {outer_attempt})...")

        # Generate fresh A pairs for all rounds
        proofs_for_0 = [gen_proof_for_challenge0() for _ in range(128)]
        proofs_for_1 = [gen_proof_for_challenge1() for _ in range(128)]

        # Try fixed-point iteration
        assignment = [0] * 128  # Start all type-0

        for inner in range(300):
            new_assignment = compute_challenges(proofs_for_0, proofs_for_1, assignment)

            if new_assignment == assignment:
                print(f"[+] Fixed point found! (outer={outer_attempt}, inner={inner+1})")
                return proofs_for_0, proofs_for_1, assignment

            assignment = new_assignment

        # Didn't converge, try new A pairs


class Connection:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(120)
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
        self.s.sendall(json.dumps(obj).encode() + b'\n')


def main():
    print("[*] Finding fixed point assignment...")
    proofs_for_0, proofs_for_1, assignment = find_fixed_point()

    ones = sum(assignment)
    print(f"[*] Assignment: {ones} type-1, {128-ones} type-0")

    print("[*] Connecting to server...")
    conn = Connection()
    conn.recv_until(b"prove to me that G has a hamiltonian cycle!\n")

    for i in range(128):
        A, z = proofs_for_0[i] if assignment[i] == 0 else proofs_for_1[i]
        conn.recv_until(b"fiat shamir proof: ")
        conn.send_json({"A": A, "z": z})
        if (i + 1) % 16 == 0:
            print(f"  Sent {i+1}/128")

    print("[*] All sent, reading result...")
    try:
        while True:
            line = conn.recv_line()
            if line:
                print(f"  {line}")
            if 'crypto{' in line:
                print(f"\n[+] FLAG: {line}")
                break
    except Exception as e:
        print(f"  Done: {e}")


if __name__ == '__main__':
    main()
