"""
Noise Cheap (Lattices / Learning With Errors 2) — POC solver

Challenge (13413.py):  b = A . S + m + p * e   (mod q)
  n = 64        (LWE dimension)
  p = 257       (plaintext modulus)
  q = 1048583   (prime, ≈ 2^20)
  e ∈ {-1, 0, 1}, so the raw noise p*e ∈ {-257, 0, 257}

Attack (primal lattice, short-secret embedding):

1. Divide out p. Since gcd(p, q) = 1, multiply every sample by p^{-1} mod q:
       A'_i = A_i * p^{-1}        c_i = b_i * p^{-1}
   and the relation becomes
       c_i ≡ A'_i . S + e_i       (mod q)   with   e_i ∈ {-1, 0, 1}
   i.e. tiny integer noise.

2. Transform to SHORT SECRET. Take the first n noisy samples and assume the
   A'_0 square matrix is invertible. Then
       S ≡ A'_0^{-1} (c_0 - e_0)   (mod q)
   with the new "secret" e_0 ∈ {-1, 0, 1}^n (unknown but SMALL).

   For every extra sample i > n, define  w_i = (A'_0^{-T}) A'_i  (mod q). Plugging in:
       c_i = A'_i . S + e_i
           = A'_i . (A'_0^{-1} (c_0 - e_0)) + e_i
           = w_i^T (c_0 - e_0) + e_i
           = w_i^T c_0 - w_i^T e_0 + e_i
   Move the known part to the LHS:
       y_i := c_i - w_i^T c_0 ≡ e_i - w_i^T e_0   (mod q)
   For all extra samples (m = total - n of them):
       y ≡ -W e_0 + e_new          (mod q),       W ∈ Z_q^{m×n}

3. Primal embedding. Construct an (n + m) × (n + m) basis:

       B = [  I_n     -W^T ]
           [  0        q·I  ]

   A lattice row (x, -W x + q k) has difference (x, -W x + q k - y) from the
   target (0, y). For x = e_0 and k chosen so -W e_0 + q k = y - e_new, the
   difference becomes (e_0, -e_new) — every coordinate in {-1, 0, 1}. Its
   norm is at most sqrt(n + m).

4. Run LLL (olll) then Babai nearest-plane to find that closest vector.
   Read off e_0, recover S, decrypt the flag.

Sample budget: n = 64, m ≈ 40 extra  →  lattice dim 104. olll handles it.
"""
import ast
import json
import socket
import sys
from pathlib import Path

from flint import fmpz_mat

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools"))
import fast_lll  # noqa: E402  (Babai NP only)

HOST = "socket.cryptohack.org"
PORT = 13413
TIMEOUT = 30

n = 64
p = 257
q = 1048583


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
        raise ConnectionError("server closed")
    return json.loads(line.decode())


def parse_A(raw: str):
    return [int(x) for x in ast.literal_eval(raw)]


# ---------- linear algebra mod q ----------
def mat_inv_mod(M, mod):
    n = len(M)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if aug[r][col] % mod != 0:
                piv = r
                break
        if piv is None:
            return None
        aug[col], aug[piv] = aug[piv], aug[col]
        inv = pow(aug[col][col] % mod, -1, mod)
        aug[col] = [(x * inv) % mod for x in aug[col]]
        for r in range(n):
            if r != col and aug[r][col] % mod != 0:
                factor = aug[r][col] % mod
                aug[r] = [(aug[r][k] - factor * aug[col][k]) % mod for k in range(2 * n)]
    return [row[n:] for row in aug]


def mat_vec_mul_mod(A, v, mod):
    return [sum(a * x for a, x in zip(row, v)) % mod for row in A]


def mat_transpose(A):
    return [list(col) for col in zip(*A)]


# ---------- sample collection ----------
def collect_samples(f, count: int):
    Ars, brs = [], []
    while len(Ars) < count:
        resp = query(f, {"option": "encrypt", "message": 0})
        if "A" not in resp:
            raise RuntimeError(f"unexpected: {resp}")
        Ars.append(parse_A(resp["A"]))
        brs.append(int(resp["b"]))
    return Ars, brs


# ---------- attack ----------
def recover_secret(f, extra: int = 60):
    p_inv = pow(p, -1, q)

    total = n + extra
    while True:
        print(f"[*] fetching {total} LWE samples from server...")
        Ars, brs = collect_samples(f, total)

        Asc = [[(a * p_inv) % q for a in row] for row in Ars]
        bsc = [(b * p_inv) % q for b in brs]

        A0 = [Asc[i][:] for i in range(n)]
        b0 = bsc[:n]

        A0_inv = mat_inv_mod(A0, q)
        if A0_inv is None:
            print("[*] first n samples singular — collecting more")
            total += 4
            continue
        break

    A0invT = mat_transpose(A0_inv)
    Wrows = []
    ys = []
    for i in range(n, total):
        w = mat_vec_mul_mod(A0invT, Asc[i], q)
        y_i = (bsc[i] - sum(wj * cj for wj, cj in zip(w, b0))) % q
        Wrows.append(w)
        ys.append(y_i)

    m = len(Wrows)

    # Build basis
    basis = []
    for j in range(n):
        row = [0] * (n + m)
        row[j] = 1
        for i in range(m):
            row[n + i] = (-Wrows[i][j]) % q
        basis.append(row)
    for i in range(m):
        row = [0] * (n + m)
        row[n + i] = q
        basis.append(row)

    target = [0] * n + [y % q for y in ys]

    print(f"[*] running flint LLL on {n + m}-dim lattice...")
    M = fmpz_mat(basis)
    M_red = M.lll()
    reduced = [[int(M_red[i, j]) for j in range(n + m)] for i in range(n + m)]
    print("[*] LLL done")

    closest = fast_lll.babai_nearest_plane(reduced, target)
    diff = [target[k] - closest[k] for k in range(len(target))]
    e0 = [int(round(x)) for x in diff[:n]]

    print(f"[*] e_0 head: {e0[:10]}")
    if not all(v in (-1, 0, 1) for v in e0):
        print(f"[!] e_0 out of range: {sorted(set(e0))}")
        return None

    # Sanity: check residuals
    residuals = diff[n:]
    if not all(abs(round(r)) <= 1 for r in residuals):
        print(f"[!] residuals too large: max={max(abs(round(r)) for r in residuals)}")
        # still continue; the real test is recovering S and verifying flag

    c0_minus_e0 = [(b0[i] - e0[i]) % q for i in range(n)]
    S = mat_vec_mul_mod(A0_inv, c0_minus_e0, q)

    # Verify against all collected samples
    bad = 0
    for A, b in zip(Ars, brs):
        d = (b - sum(a * s for a, s in zip(A, S))) % q
        if d > q // 2:
            d -= q
        if d not in (-p, 0, p):
            bad += 1
    print(f"[*] S verification: {bad}/{len(Ars)} samples inconsistent")
    if bad > 0:
        return None
    return S


def leak_flag(f, S):
    flag = []
    i = 0
    while True:
        resp = query(f, {"option": "get_flag", "index": i})
        if "error" in resp:
            break
        A = parse_A(resp["A"])
        b = int(resp["b"])
        d = (b - sum(a * s for a, s in zip(A, S))) % q
        if d > q // 2:
            d -= q
        # d = m + p*e, so d mod p = m (since m < p)
        m = d % p
        if m >= 256:
            raise RuntimeError(f"flag byte {m} out of range at {i}")
        flag.append(m)
        i += 1
        if i >= 128:
            break
    return bytes(flag)


def main() -> None:
    host, port = HOST, PORT
    if len(sys.argv) > 1 and sys.argv[1] == "--local":
        host, port = "127.0.0.1", 13413
        print(f"[*] using local server {host}:{port}")

    sock, f = open_session(host, port)
    try:
        S = recover_secret(f)
        if S is None:
            print("[-] secret recovery failed")
            return
        print(f"[+] S recovered, first 5: {S[:5]}")
        flag = leak_flag(f, S)
        print(f"[+] FLAG: {flag.decode(errors='replace')}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
