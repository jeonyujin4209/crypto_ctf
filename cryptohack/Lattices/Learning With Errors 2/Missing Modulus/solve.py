"""
Missing Modulus (Learning With Errors 2) — POC solver

The LWE encryption oracle computes  b = A·S + m·delta + e  *without* any
mod-q reduction (note the missing `% q` — that's the bug). So every sample
is an INTEGER linear equation in S with very small Gaussian noise:

    b_i = (A_i, S) + m·delta + e_i        (over Z)

with σ(e) = 3.8, n = 512, q = 6007 (only used to sample A and S, not as a
modulus on b).

Attack: ask the oracle for n encryptions of m=0:

    b_i = (A_i, S) + e_i

Stack into a square integer system A·S = b - e. Since A is a random integer
matrix with entries in [-q/2, q/2] and e_i is tiny (~σ √n ≈ 86) while the
LHS is huge (≈ q √n √n ≈ 3×10^6), the noise is far below the matrix's
condition-number floor. Solve A·x = b over Q (numpy.linalg.solve in float64
is precise enough; or use rational solve via sympy/fractions if paranoid)
then round to the nearest integer to recover S.

With S in hand, every flag-byte query (A_i, b_i) gives
    flag[i] = round((b_i - (A_i, S)) / delta).
"""
import ast
import json
import socket
import sys

import numpy as np

HOST = "socket.cryptohack.org"
PORT = 13412
TIMEOUT = 30

n = 512
p = 257
q = 6007
delta = round(q / p)
FLAG_LEN = 46  # crypto{...} 길이 (확인 후 수정)


def query(f, payload):
    f.write((json.dumps(payload) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    return json.loads(line.decode())


def parse_A(raw):
    return [int(x) for x in ast.literal_eval(raw)]


def main():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # greeting

    print(f"[*] collecting {n} m=0 samples...")
    A_rows = []
    b_vals = []
    for _ in range(n):
        r = query(f, {"option": "encrypt", "message": 0})
        A_rows.append(parse_A(r["A"]))
        b_vals.append(int(r["b"]))
    A = np.array(A_rows, dtype=np.float64)
    b = np.array(b_vals, dtype=np.float64)

    print("[*] solving A · S = b over R, rounding to integers...")
    S_float = np.linalg.solve(A, b)
    S = np.round(S_float).astype(np.int64)
    # Sanity: residual should be tiny
    resid = A @ S.astype(np.float64) - b
    print(f"    max residual = {np.max(np.abs(resid)):.2f}  (expected: small Gaussian noise)")
    if np.max(np.abs(resid)) > 50:
        print("[!] residual too big — re-collect more samples")

    print("[*] leaking flag bytes...")
    flag_bytes = []
    for i in range(FLAG_LEN):
        r = query(f, {"option": "get_flag", "index": i})
        if "error" in r:
            break
        A_i = np.array(parse_A(r["A"]), dtype=np.int64)
        b_i = int(r["b"])
        # b_i = A_i · S + flag[i] * delta + e
        residual = b_i - int(np.dot(A_i, S))
        # residual ≈ flag[i] * delta + e
        flag_byte = round(residual / delta)
        if 0 <= flag_byte < 256:
            flag_bytes.append(flag_byte)
        else:
            print(f"[!] byte {i}: residual={residual}, computed={flag_byte}")
            flag_bytes.append(63)  # ?
    sock.close()

    flag = bytes(flag_bytes)
    print(f"FLAG: {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
