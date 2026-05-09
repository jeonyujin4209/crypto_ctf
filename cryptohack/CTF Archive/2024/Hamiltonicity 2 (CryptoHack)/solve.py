"""
Hamiltonicity 2 — Fiat-Shamir collision via separator-less str-join in hash_committed_graph.

Vulnerability:
  hash_committed_graph builds first_message = "".join(str(x) for row in G for x in row).
  No separator → two different 5x5 matrices with the same flat str-concatenation hash equally.

Attack (no DLP needed):
  For each round prepare both A_a (valid for type 0) and A_b (valid for type 1) such that
  fm_a == fm_b. Hash chain is identical for either choice, so we predict the challenge bits
  before deciding which matrix to send per round.

  A_a: honest commit_to_graph(G).
  A_b: 5 cycle-position cells reuse A_a's commit-to-1 cells (at G's 1-positions S_a) via a
       bijection σ: S_b → S_a. Other 20 cells are JSON strings whose lengths are picked so
       that each cycle cell in A_b lands at the same character offset as σ(p) in fm_a.

  Cycle 0→1→3→2→4→0 → S_b sorted = {1, 8, 14, 17, 20} (gaps ≥ 3).
  G's 1-positions   → S_a sorted = {2, 5, 11, 19, 23}.
  Order-preserving σ: 1→2, 8→5, 14→11, 17→19, 20→23.

  All 5 group-slacks are non-negative and have ≥1 free cell to absorb them, so feasible.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hamiltonicity import (
    commit_to_graph, hash_committed_graph, comm_params,
    open_graph, permute_graph, testcycle,
)

P, q, h1, h2 = comm_params

NUMROUNDS = 128
N = 5
G = [
    [0,0,1,0,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,0,1,0],
]

CYCLE_NODES = [(0,1), (1,3), (3,2), (2,4), (4,0)]
S_b_sorted = sorted({5*s+d for (s,d) in CYCLE_NODES})        # [1, 8, 14, 17, 20]
S_a_sorted = sorted({5*i+j for i in range(N) for j in range(N) if G[i][j] == 1})  # [2, 5, 11, 19, 23]
SIGMA = dict(zip(S_b_sorted, S_a_sorted))
S_b_set = set(S_b_sorted)


def build_round():
    """Return (A_a, A_b, openings_a, cycle_openings)."""
    A_a, openings_a = commit_to_graph(G, N)
    lengths = [len(str(A_a[k//N][k%N])) for k in range(25)]
    offset_a = [0] * 26
    for k in range(25):
        offset_a[k+1] = offset_a[k] + lengths[k]
    fm_a = ''.join(str(A_a[k//N][k%N]) for k in range(25))

    L = [0] * 25
    boundaries = [-1] + S_b_sorted + [25]
    cur = 0
    for g in range(len(boundaries) - 1):
        start = boundaries[g] + 1
        end = boundaries[g+1]
        if g == len(boundaries) - 2:
            target_end = offset_a[25]
        else:
            target_end = offset_a[SIGMA[end]]
        slack = target_end - cur
        free_positions = list(range(start, end))
        if free_positions:
            L[free_positions[-1]] = slack
        else:
            assert slack == 0
        cur = target_end
        if end < 25:
            cur += lengths[SIGMA[end]]

    A_b = [[None]*N for _ in range(N)]
    pos = 0
    for r in range(25):
        i, j = r // N, r % N
        if r in S_b_set:
            sa = SIGMA[r]
            A_b[i][j] = A_a[sa // N][sa % N]
            pos += lengths[sa]
        else:
            A_b[i][j] = fm_a[pos : pos + L[r]]
            pos += L[r]

    fm_b = ''.join(str(A_b[k//N][k%N]) for k in range(25))
    assert fm_b == fm_a

    cycle_openings = []
    for (s, d) in CYCLE_NODES:
        sa = SIGMA[5*s+d]
        m, rr = openings_a[sa // N][sa % N]
        assert m == 1
        cycle_openings.append(rr)

    return A_a, A_b, openings_a, cycle_openings


def build_proofs():
    rounds = [build_round() for _ in range(NUMROUNDS)]

    FS_state = b''
    for A_a, _A_b, _o, _co in rounds:
        FS_state = hash_committed_graph(A_a, FS_state, comm_params)
    challenge_bits = bin(int.from_bytes(FS_state, 'big'))[-NUMROUNDS:]
    assert len(challenge_bits) == NUMROUNDS and set(challenge_bits) <= {'0','1'}, \
        f"unlucky FS_state high-bit; got {challenge_bits[:5]}..."

    proofs = []
    for i, (A_a, A_b, openings_a, cycle_openings) in enumerate(rounds):
        bit = int(challenge_bits[i])
        if bit == 1:
            cycle_list = [list(c) for c in CYCLE_NODES]
            proofs.append({"A": A_b, "z": [cycle_list, cycle_openings]})
        else:
            proofs.append({"A": A_a, "z": [[0,1,2,3,4], openings_a]})
    return proofs, challenge_bits


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "local"

    proofs, bits = build_proofs()
    print(f"[+] built {len(proofs)} proofs; type1 count = {bits.count('1')}", file=sys.stderr)

    if target == "local":
        # spawn chal.py via pwntools
        from pwn import process
        env = dict(os.environ)
        env["FLAG"] = "TEST{local_attack_works}"
        rem = process(["python", "chal.py"], env=env, cwd=os.path.dirname(os.path.abspath(__file__)))
    else:
        from pwn import remote
        host, port = target.split(":")
        rem = remote(host, int(port))

    rem.recvuntil(b"prove to me that G has a hamiltonian cycle!")
    for i, pr in enumerate(proofs):
        rem.recvuntil(b"send fiat shamir proof: ")
        rem.sendline(json.dumps(pr).encode())
    out = rem.recvall(timeout=60)
    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()
