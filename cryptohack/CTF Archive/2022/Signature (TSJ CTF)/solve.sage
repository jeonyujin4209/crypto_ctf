"""Sage lattice attack for Signature (TSJ CTF 2022).

Reads from stdin: 18 whitespace-separated ints (6 triples of z, r, s).
Writes d to stdout.

Vulnerability: nonce k = d XOR z (known z). Per-bit:
  k = z + Σ_i d_i · 2^i · (1 - 2·z_i)
So s·k ≡ z + r·d mod q becomes:
  Σ_i d_i · 2^i · (s·(1 - 2·z_i) - r) ≡ z·(1 - s) mod q   (d_i ∈ {0,1})

6 equations × 256 bits → Kannan embedding lattice, LLL reveals d.
"""
from sage.all import *
import sys
import time


def build_lattice(sigs, Q, N=256):
    A = []
    C = []
    for z, r, s in sigs:
        row = []
        for i in range(N):
            zi = (z >> i) & 1
            coef = (pow(2, i, Q) * (s * (1 - 2 * zi) - r)) % Q
            row.append(coef)
        A.append(row)
        C.append((z * (1 - s)) % Q)
    return A, C


def run_lll(A, C, Q, N=256):
    nsig = len(A)
    dim = N + nsig + 1
    K = Q
    B = Matrix(ZZ, dim, dim)
    for i in range(N):
        B[i, i] = 1
        for j in range(nsig):
            B[i, N + j] = K * A[j][i]
    for j in range(nsig):
        B[N + j, N + j] = K * Q
    for j in range(nsig):
        B[N + nsig, N + j] = K * C[j]
    B[N + nsig, N + nsig] = 1
    print(f"[*] dim = {dim}", file=sys.stderr)
    t0 = time.time()
    Br = B.LLL()
    print(f"[*] LLL {time.time() - t0:.1f}s", file=sys.stderr)
    return Br


def extract_d(Br, N=256, nsig=6):
    for row in Br:
        last = int(row[-1])
        if abs(last) != 1:
            continue
        modpart = [int(row[N + j]) for j in range(nsig)]
        if any(m != 0 for m in modpart):
            continue
        sign = -last
        bits = [sign * int(row[i]) for i in range(N)]
        if all(b in (0, 1) for b in bits):
            return sum(b * (1 << i) for i, b in enumerate(bits))
    return None


def verify_d(d, sigs, Q):
    for z, r, s in sigs:
        k = int(d) ^^ int(z)
        if (s * k - z - r * d) % Q != 0:
            return False
    return True


def main():
    data = sys.stdin.read().strip().split()
    sigs = []
    for i in range(0, len(data), 3):
        sigs.append((int(data[i]), int(data[i + 1]), int(data[i + 2])))
    Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    A, C = build_lattice(sigs, Q)
    Br = run_lll(A, C, Q)
    d = extract_d(Br, nsig=len(sigs))
    if d is None:
        print("[!] FAILED: no valid {0,1} vector found", file=sys.stderr)
        sys.exit(1)
    if not verify_d(d, sigs, Q):
        print(f"[!] FAILED: d = {d} did not verify", file=sys.stderr)
        sys.exit(1)
    print(f"[+] d = {d}", file=sys.stderr)
    print(d)


main()
