"""
Noise Free (Lattices / Learning With Errors 2) — POC solver

Challenge (13411.py): LWE without any error. Dimension n=64, q=0x10001.
Server picks a random S in Z_q^n, then on each query returns (A, b) where
  b = A.S + m   (mod q)
for m chosen by us (option=encrypt) or m=FLAG[i] (option=get_flag).

With NO noise, every query is a linear equation in S over Z_q. Send 64
encrypt(m=0) queries and stack them:
  M . S = bvec  (mod q)        where M is 64x64 and bvec is 64x1
If M is invertible, S = M^{-1} . bvec.

With S known, `get_flag(i)` gives (A_i, b_i) and the flag byte is
  FLAG[i] = (b_i - A_i . S) mod q
(mod q is fine because all flag bytes are <256 < q).
"""
import ast
import json
import socket
import sys

HOST = "socket.cryptohack.org"
PORT = 13411
TIMEOUT = 15

n = 64
q = 0x10001


def gauss_solve_mod(A, b, mod):
    """Solve A x = b (mod prime modulus). Returns x. A is n x n list-of-lists."""
    n_rows = len(A)
    M = [row[:] + [bi] for row, bi in zip(A, b)]
    for col in range(n_rows):
        # Find pivot
        pivot = None
        for r in range(col, n_rows):
            if M[r][col] % mod != 0:
                pivot = r
                break
        if pivot is None:
            raise RuntimeError(f"singular system at column {col}")
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]
        inv = pow(M[col][col] % mod, -1, mod)
        M[col] = [(x * inv) % mod for x in M[col]]
        for r in range(n_rows):
            if r != col and M[r][col] % mod != 0:
                factor = M[r][col] % mod
                M[r] = [(M[r][k] - factor * M[col][k]) % mod for k in range(n_rows + 1)]
    return [M[i][n_rows] % mod for i in range(n_rows)]


def open_session(host: str, port: int):
    sock = socket.create_connection((host, port))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # greeting
    return sock, f


def query(f, payload: dict) -> dict:
    f.write((json.dumps(payload) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed unexpectedly")
    return json.loads(line.decode())


def parse_A(raw: str):
    return [int(x) for x in ast.literal_eval(raw)]


def recover_secret(f):
    """Collect n independent (A_i, b_i) with m=0 and solve for S."""
    rows = []
    bs = []
    while len(rows) < n:
        resp = query(f, {"option": "encrypt", "message": 0})
        if "A" not in resp:
            raise RuntimeError(f"unexpected encrypt response: {resp}")
        A = parse_A(resp["A"])
        b = int(resp["b"])
        rows.append(A)
        bs.append(b)

    # Solve rows * S = bs over GF(q) via Gaussian elimination.
    S = gauss_solve_mod(rows, bs, q)
    return S


def leak_flag(f, S):
    # First find the flag length: query get_flag with incrementing index until error.
    # We know FLAG in the file is 32 bytes ("crypto{????????????????????????}"),
    # but probe to be safe (up to 128).
    flag_bytes = []
    i = 0
    while True:
        resp = query(f, {"option": "get_flag", "index": i})
        if "error" in resp:
            break
        A = parse_A(resp["A"])
        b = int(resp["b"])
        dot = sum(a * s for a, s in zip(A, S)) % q
        m = (b - dot) % q
        if m >= 256:
            raise RuntimeError(f"unexpected flag byte {m} at index {i}")
        flag_bytes.append(m)
        i += 1
        if i >= 128:
            break
    return bytes(flag_bytes)


def main() -> None:
    host, port = HOST, PORT
    if len(sys.argv) > 1 and sys.argv[1] == "--local":
        host, port = "127.0.0.1", 13411
        print(f"[*] using local server {host}:{port}")

    sock, f = open_session(host, port)
    try:
        print("[*] collecting 64 zero-message encryptions to recover S...")
        S = recover_secret(f)
        print(f"[+] S recovered ({len(S)} coeffs), first 5: {S[:5]}")

        print("[*] leaking flag bytes...")
        flag = leak_flag(f, S)
        print(f"[+] FLAG: {flag.decode(errors='replace')}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
