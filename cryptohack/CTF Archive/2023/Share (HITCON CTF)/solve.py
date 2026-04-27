"""
Share (HITCON CTF) — Shamir Secret Sharing with biased coefficients.

Vulnerability:
    Server picks polynomial coefficients via getRandomRange(0, p-1),
    which returns values in [0, p-2]. So no coefficient ever equals p-1 mod p.
    With n-1 shares of a degree-(n-1) polynomial, parametrize by the missing
    share s_n: each coefficient a_k is an affine function of s_n. The constraint
    "a_k != p-1 mod p" rules out one s_n per (k>=1) constraint, leaving roughly
    p/3 valid s_n in practice. Thus secret mod p has ~p/3 candidates per query.

Attack:
    For each prime p in a list whose product exceeds 2^256, run several queries
    with n = p-1 (max info). Intersect candidate sets across queries until
    unique → secret mod p. CRT to recover full secret.

    Server allows any (p, n) with isPrime(p), 13 < n < p, single secret per
    connection, signal.alarm(30).

Run: python solve.py [host] [port]
"""
import socket
import sys
import time
import re
from sympy import nextprime
from sympy.ntheory.modular import crt


def precompute_lagrange(p, n):
    """L_i(x) coefficients mod p for x_i = 1..n, returned as Lcoeffs[i][k]."""
    xs = list(range(1, n + 1))

    def poly_mul(a, b):
        c = [0] * (len(a) + len(b) - 1)
        for i, ai in enumerate(a):
            if ai == 0: continue
            for j, bj in enumerate(b):
                c[i+j] = (c[i+j] + ai * bj) % p
        return c

    L = []
    for i in range(n):
        poly = [1]
        denom = 1
        for j in range(n):
            if i == j: continue
            poly = poly_mul(poly, [(-xs[j]) % p, 1])
            denom = denom * (xs[i] - xs[j]) % p
        inv = pow(denom, -1, p)
        poly = [(c * inv) % p for c in poly]
        while len(poly) < n: poly.append(0)
        L.append(poly)
    return L


def candidates_from_shares(partial_shares, p, n, Lcoeffs):
    """Return set of candidate secret values mod p given n-1 shares."""
    fixed = [0]*n
    for k in range(n):
        v = 0
        for i in range(n-1):
            v = (v + partial_shares[i] * Lcoeffs[i][k]) % p
        fixed[k] = v
    B = [Lcoeffs[n-1][k] for k in range(n)]

    cands = set()
    for sn in range(p):
        ok = True
        for k in range(1, n):
            ak = (fixed[k] + sn * B[k]) % p
            if ak == p-1:
                ok = False
                break
        if ok:
            cands.add((fixed[0] + sn * B[0]) % p)
    return cands


SHARES_RE = re.compile(rb"shares\s*=\s*(\[[^\]]*\])")


class Net:
    def __init__(self, host, port):
        self.sock = socket.socket()
        self.sock.connect((host, port))
        self.sock.settimeout(30)
        self.buf = b""

    def recv_until_shares(self):
        """Read until we capture a 'shares = [...]' line; return parsed list."""
        while True:
            m = SHARES_RE.search(self.buf)
            if m:
                arr = eval(m.group(1).decode())
                # Trim buffer past match
                self.buf = self.buf[m.end():]
                return arr
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"EOF, buf={self.buf[-200:]!r}")
            self.buf += chunk

    def recv_until(self, marker):
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"EOF, buf={self.buf!r}")
            self.buf += chunk
        idx = self.buf.index(marker)
        out = self.buf[:idx + len(marker)]
        self.buf = self.buf[idx + len(marker):]
        return out

    def send(self, data):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "archive.cryptohack.org"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12739

    # Build prime plan: pick primes that balance info/query against compute.
    primes = []
    prod = 1
    p = 13
    while prod.bit_length() < 270:
        p = nextprime(p)
        primes.append(p)
        prod *= p
    print(f"[*] using {len(primes)} primes up to {primes[-1]}, prod bits {prod.bit_length()}", flush=True)

    # Precompute Lagrange tables (client-side, one-time)
    print("[*] precomputing Lagrange tables...", flush=True)
    t0 = time.time()
    Ltables = {}
    for p in primes:
        n = p - 1
        Ltables[p] = precompute_lagrange(p, n)
    print(f"[*] precompute done in {time.time()-t0:.2f}s", flush=True)

    # Connect
    print(f"[*] connecting to {host}:{port}", flush=True)
    net = Net(host, port)

    found = {}
    total_queries = 0

    t_start = time.time()
    # Pipeline strategy: send a big batch of (p, n) pairs at once, then read all responses.
    # Each prime needs ~5 queries; do 8 per prime to be safe, then process.
    BATCH_PER_PRIME = 8  # most primes settle in 4-7; 8 covers most

    # Build full batch
    batch_lines = []
    for p in primes:
        n = p - 1
        for _ in range(BATCH_PER_PRIME):
            batch_lines.append(f"{p}\n{n}\n".encode())
    big = b"".join(batch_lines)
    print(f"[*] sending {len(big)} bytes ({len(batch_lines)} queries)", flush=True)
    net.send(big)

    # Now receive all responses, one per query, in order
    expected = len(batch_lines)
    all_shares = []
    for i in range(expected):
        shares = net.recv_until_shares()
        all_shares.append(shares)
        if (i+1) % 50 == 0:
            print(f"[*] received {i+1}/{expected}, t={time.time()-t_start:.1f}s", flush=True)
    print(f"[*] all received in {time.time()-t_start:.1f}s", flush=True)

    # Process per prime — must consume all BATCH_PER_PRIME slots per prime to stay aligned
    cand_sets = {}
    idx = 0
    for p in primes:
        n = p - 1
        Lc = Ltables[p]
        cand_set = None
        for q in range(BATCH_PER_PRIME):
            shares = all_shares[idx]
            idx += 1
            if len(shares) != n - 1:
                print(f"[!] p={p} n={n} q={q} idx={idx-1}: got {len(shares)} shares, expected {n-1}", flush=True)
                sys.exit(1)
            if cand_set is None or len(cand_set) > 1:
                cands = candidates_from_shares(shares, p, n, Lc)
                cand_set = cands if cand_set is None else cand_set & cands
        cand_sets[p] = cand_set

    # Retry primes that didn't converge with extra queries
    while any(len(cs) > 1 for cs in cand_sets.values()):
        unresolved = [p for p in primes if len(cand_sets[p]) > 1]
        print(f"[*] retry round: {len(unresolved)} primes unresolved", flush=True)
        EXTRA = 6
        retry_lines = []
        for p in unresolved:
            n = p - 1
            for _ in range(EXTRA):
                retry_lines.append(f"{p}\n{n}\n".encode())
        net.send(b"".join(retry_lines))
        retry_count = len(unresolved) * EXTRA
        retry_shares = []
        for i in range(retry_count):
            retry_shares.append(net.recv_until_shares())
        # Process
        idx2 = 0
        for p in unresolved:
            n = p - 1
            Lc = Ltables[p]
            cs = cand_sets[p]
            for _ in range(EXTRA):
                shares = retry_shares[idx2]; idx2 += 1
                if len(cs) > 1:
                    new_cands = candidates_from_shares(shares, p, n, Lc)
                    cs = cs & new_cands
            cand_sets[p] = cs

    found = {p: next(iter(cs)) for p, cs in cand_sets.items()}
    total_queries = expected

    # Break out of loop with invalid input (n=4 not >13)
    net.send(b"5\n4\n")
    # Wait for "secret = " prompt
    net.recv_until(b"secret = ")

    # CRT
    rems = [found[p] for p in primes]
    secret, M = crt(primes, rems)
    secret = int(secret)
    print(f"[+] secret = {secret}", flush=True)
    net.send(f"{secret}\n".encode())

    net.sock.settimeout(5)
    rest = b""
    try:
        while True:
            d = net.sock.recv(4096)
            if not d: break
            rest += d
    except Exception:
        pass
    print("[server]", (net.buf + rest).decode(errors="replace"))


if __name__ == "__main__":
    main()
