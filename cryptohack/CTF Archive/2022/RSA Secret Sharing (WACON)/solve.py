"""Solve RSA Secret Sharing (WACON 2022) at archive.cryptohack.org:42957.

Vulnerability / attack:
  Server generates q = 342-bit prime, 3 LCGs. User supplies (a,x,b) for LCG1.
  Each "roll" yields `L3.fetch()*q^2 + L2.fetch()*q + L1.fetch()`; 8 primes are
  selected, forming 4 RSA moduli n_1..n_4. User must factor all 4.

  Set LCG1 = (a=1, x=1, b=1) ⇒ L1_i = 1+i (= 1 + roll index).
  Then for each modulus n_k = p_a * p_b:
    n_k mod q  = (1+r_a)(1+r_b)                             ← small int, factor it
    n_k mod q² − (1+r_a)(1+r_b) = q·(L2_a·(1+r_b) + L2_b·(1+r_a)) mod q²
  so we read B_k = L2_a·(1+r_b) + L2_b·(1+r_a) mod q.

  With LCG2 recurrence L2_i = α·a₂^i + β, 4 B_k equations → polynomial in a₂
  (take det of 3×3 augmented matrix). Root-find mod q → recover (a₂, α, β).
  Each prime then has (L1, L2) known ⇒ p mod q² known (684 of 1026 bits).
  Coppersmith small_roots(X=q, β=0.5) factors each n_k. (X = q ≈ N^{1/6} < N^{1/4}.)

  PoW: sha256(s+ans) with low 26 bits == 0  (expected ~67M tries, ~36 s).
"""

import hashlib
import os
import socket
import subprocess
import sys
import time


HOST = "archive.cryptohack.org"
PORT = 42957


# ---------- network helpers ----------

def recv_line(sock):
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        buf.extend(ch)
        if ch == b"\n":
            break
    return buf.decode(errors="replace").rstrip("\r\n")


# ---------- PoW ----------

def solve_pow(s):
    """Find ans such that low 26 bits of sha256(s+ans) are zero."""
    sb = s.encode()
    i = 0
    while True:
        ans = str(i).encode()
        h = hashlib.sha256(sb + ans).digest()
        if h[-3:] == b"\x00\x00\x00" and (h[-4] & 0x03) == 0:
            return ans.decode()
        i += 1


# ---------- attack via Sage subprocess ----------

def run_sage_attack(q, ns, timeout=900):
    """Run attack.sage in docker, return list of 8 prime factors."""
    input_str = f"{q}\n" + "\n".join(str(n) for n in ns) + "\n"
    wdir = os.path.abspath(os.path.dirname(__file__) or ".").replace("D:", "/d").replace("\\", "/")
    cmd = [
        "docker", "run", "--rm", "-i",
        "-v", f"{wdir}:/work", "-w", "/work",
        "sagemath/sagemath:latest", "sage", "attack.sage",
    ]
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    res = subprocess.run(cmd, input=input_str, capture_output=True, text=True, timeout=timeout, env=env)
    sys.stderr.write(res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"sage attack failed (rc={res.returncode})")
    lines = [l.strip() for l in res.stdout.strip().split("\n") if l.strip()]
    return [int(l) for l in lines]


# ---------- main protocol ----------

def main(host=HOST, port=PORT):
    s = socket.create_connection((host, port), timeout=1800)
    # PoW prompt
    line = recv_line(s)
    print(f"<< {line}")
    pow_s = recv_line(s)
    print(f"<< pow challenge: {pow_s}")
    t0 = time.time()
    ans = solve_pow(pow_s)
    print(f"PoW solved in {time.time()-t0:.1f}s: {ans}")
    s.sendall((ans + "\n").encode())

    # q
    line = recv_line(s)
    print(f"<< {line}")
    q = int(line.split("=")[1].strip())

    # Hello + parameter prompt; send our LCG1 = (1, 1, 1)
    hello = recv_line(s)
    print(f"<< {hello}")
    for val in ("1", "1", "1"):
        s.sendall((val + "\n").encode())

    # 4 moduli
    ns = []
    for k in range(4):
        ns.append(int(recv_line(s)))
    print(f"Received 4 moduli, bit-lengths: {[n.bit_length() for n in ns]}")
    print(f"q bit-length: {q.bit_length()}")

    # Run attack
    t1 = time.time()
    ps = run_sage_attack(q, ns)
    print(f"Attack done in {time.time()-t1:.1f}s, got {len(ps)} factors")
    assert len(ps) == 8
    for k in range(4):
        u, v = ps[2*k], ps[2*k+1]
        assert u * v == ns[k], f"Factorization failed for n_{k}"
    print("All factorizations verified locally")

    # Submit
    for k in range(4):
        u, v = ps[2*k], ps[2*k+1]
        s.sendall((str(u) + "\n").encode())
        s.sendall((str(v) + "\n").encode())
    print("Submitted all factorizations")

    # Read remainder (flag)
    s.settimeout(15)
    rest = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            rest += chunk
    except socket.timeout:
        pass
    print("SERVER RESPONSE:")
    print(rest.decode(errors="replace"))


if __name__ == "__main__":
    h, p = HOST, PORT
    if len(sys.argv) >= 3:
        h = sys.argv[1]
        p = int(sys.argv[2])
    main(h, p)
