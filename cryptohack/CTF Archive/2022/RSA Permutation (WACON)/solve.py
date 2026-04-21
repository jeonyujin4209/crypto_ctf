"""
Solve RSA Permutation (WACON 2022) at archive.cryptohack.org:45400.

Vulnerability:
  Server gives n and d_p' = perm(hex(d_p)), d_q' = perm(hex(d_q)) under a random
  permutation of the 16 hex digits. We must return (u, v) with u*v == n.

Attack (Heninger-Shacham style branch-and-prune on hex digits):
  d_p = sum_i sigma[y_p[i]] * 16^i  (linear in unknown permutation sigma)
  Identity: (e*d_p - 1) = k_p*(p-1), (e*d_q - 1) = k_q*(q-1), p*q = n
           =>  (e*d_p + k_p - 1)*(e*d_q + k_q - 1) = k_p*k_q*n.

  Key narrowing: mod e we have k_p*(p-1) ≡ -1, so k_p ≡ -(p-1)^(-1) mod e.
  Iterating p mod e ∈ {2,...,e-1} fully determines (k_p, k_q) via q ≡ n/p mod e.
  That yields ~290 candidate pairs instead of (e-1)^2 ≈ 85k.

  For each pair, backtrack sigma LSB-hex first, pruning by checking the equation
  mod 16^(d+1) at every depth. When sigma is fully assigned, verify exactly.
"""

import socket
import hashlib
import string
import sys
import time

sys.setrecursionlimit(50000)


# ---------- backtracking solver ----------

def backtrack_fixed(y_p, y_q, n, e, kp, kq, L, all_y):
    sigma = [-1] * 16
    used = [False] * 16
    kpkqn = kp * kq * n
    result = [None]
    assigned_count = [0]

    def verify_full():
        dp = 0
        dq = 0
        p16 = 1
        for i in range(L):
            dp += sigma[y_p[i]] * p16
            dq += sigma[y_q[i]] * p16
            p16 <<= 4
        if (e * dp - 1) % kp != 0:
            return None
        p = (e * dp - 1) // kp + 1
        if p <= 1 or p >= n or n % p != 0:
            return None
        q = n // p
        if (e * dq - 1) % (q - 1) != 0:
            return None
        return (p, q)

    def rec(depth, dp_mod, dq_mod):
        if result[0] is not None:
            return
        if assigned_count[0] == len(all_y):
            r = verify_full()
            if r is not None:
                result[0] = r
            return
        if depth >= L:
            return

        y1 = y_p[depth]
        y2 = y_q[depth]
        pow16 = 1 << (4 * depth)
        mod_new = pow16 << 4

        s1 = sigma[y1]
        s2 = sigma[y2]

        if s1 != -1 and s2 != -1:
            new_dp = dp_mod + s1 * pow16
            new_dq = dq_mod + s2 * pow16
            if ((e * new_dp + kp - 1) * (e * new_dq + kq - 1) - kpkqn) % mod_new == 0:
                rec(depth + 1, new_dp, new_dq)
            return

        if y1 == y2:
            for v in range(16):
                if used[v]:
                    continue
                new_dp = dp_mod + v * pow16
                new_dq = dq_mod + v * pow16
                if ((e * new_dp + kp - 1) * (e * new_dq + kq - 1) - kpkqn) % mod_new == 0:
                    sigma[y1] = v
                    used[v] = True
                    assigned_count[0] += 1
                    rec(depth + 1, new_dp, new_dq)
                    sigma[y1] = -1
                    used[v] = False
                    assigned_count[0] -= 1
                    if result[0] is not None:
                        return
            return

        if s1 != -1:
            for v2 in range(16):
                if used[v2]:
                    continue
                new_dp = dp_mod + s1 * pow16
                new_dq = dq_mod + v2 * pow16
                if ((e * new_dp + kp - 1) * (e * new_dq + kq - 1) - kpkqn) % mod_new == 0:
                    sigma[y2] = v2
                    used[v2] = True
                    assigned_count[0] += 1
                    rec(depth + 1, new_dp, new_dq)
                    sigma[y2] = -1
                    used[v2] = False
                    assigned_count[0] -= 1
                    if result[0] is not None:
                        return
            return

        if s2 != -1:
            for v1 in range(16):
                if used[v1]:
                    continue
                new_dp = dp_mod + v1 * pow16
                new_dq = dq_mod + s2 * pow16
                if ((e * new_dp + kp - 1) * (e * new_dq + kq - 1) - kpkqn) % mod_new == 0:
                    sigma[y1] = v1
                    used[v1] = True
                    assigned_count[0] += 1
                    rec(depth + 1, new_dp, new_dq)
                    sigma[y1] = -1
                    used[v1] = False
                    assigned_count[0] -= 1
                    if result[0] is not None:
                        return
            return

        for v1 in range(16):
            if used[v1]:
                continue
            for v2 in range(16):
                if v2 == v1 or used[v2]:
                    continue
                new_dp = dp_mod + v1 * pow16
                new_dq = dq_mod + v2 * pow16
                if ((e * new_dp + kp - 1) * (e * new_dq + kq - 1) - kpkqn) % mod_new == 0:
                    sigma[y1] = v1
                    sigma[y2] = v2
                    used[v1] = True
                    used[v2] = True
                    assigned_count[0] += 2
                    rec(depth + 1, new_dp, new_dq)
                    sigma[y1] = -1
                    sigma[y2] = -1
                    used[v1] = False
                    used[v2] = False
                    assigned_count[0] -= 2
                    if result[0] is not None:
                        return

    rec(0, 0, 0)
    return result[0]


def candidate_pairs(n, e):
    pairs = set()
    for p_me in range(2, e):
        p_inv = pow(p_me, -1, e)
        q_me = (n * p_inv) % e
        if q_me == 0 or q_me == 1:
            continue
        kp = (-pow(p_me - 1, -1, e)) % e
        kq = (-pow(q_me - 1, -1, e)) % e
        if kp == 0 or kq == 0:
            continue
        pairs.add((kp, kq))
    return list(pairs)


def solve_rsa_perm(n, dps, dqs, e=293):
    L = len(dps)
    y_p = [int(dps[L - 1 - i], 16) for i in range(L)]
    y_q = [int(dqs[L - 1 - i], 16) for i in range(L)]
    all_y = set(y_p) | set(y_q)
    pairs = candidate_pairs(n, e)
    for kp, kq in pairs:
        res = backtrack_fixed(y_p, y_q, n, e, kp, kq, L, all_y)
        if res is not None:
            return res
    return None


# ---------- PoW ----------

def solve_pow(s):
    # sha256(s + answer) needs to start with "000000" (24-bit target, ~16.7M tries expected)
    s_bytes = s.encode()
    i = 0
    target = b"\x00\x00\x00"
    while True:
        ans = str(i).encode()
        h = hashlib.sha256(s_bytes + ans).digest()
        if h[:3] == target:
            # Check the 4th hex nibble (bit 25-28) is also 0: hexdigest()[:6]==000000 means first 24 bits zero.
            # h[:3] == \x00\x00\x00 already confirms first 24 bits = 0. So we're good.
            return ans.decode()
        i += 1


# ---------- network ----------

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


def recv_all_lines(sock, n):
    lines = []
    for _ in range(n):
        lines.append(recv_line(sock))
    return lines


def main(host, port):
    s = socket.create_connection((host, port), timeout=400)
    # Solve PoW
    line1 = recv_line(s)  # "Solve PoW plz"
    print(f"<< {line1}")
    pow_s = recv_line(s)  # 16-char challenge
    print(f"<< pow string: {pow_s}")

    t0 = time.time()
    ans = solve_pow(pow_s)
    print(f"PoW answer: {ans} (took {time.time()-t0:.2f}s)")
    s.sendall((ans + "\n").encode())

    # Read n, dps, dqs
    n_line = recv_line(s)
    dps_line = recv_line(s)
    dqs_line = recv_line(s)
    n = int(n_line)
    dps = dps_line.strip()
    dqs = dqs_line.strip()
    print(f"n bit-length: {n.bit_length()}")
    print(f"dps len: {len(dps)}, dqs len: {len(dqs)}")

    t1 = time.time()
    res = solve_rsa_perm(n, dps, dqs, e=293)
    print(f"solve time: {time.time()-t1:.2f}s")
    if res is None:
        print("SOLVE FAILED")
        return
    p, q = res
    assert p * q == n
    print(f"factored! sending p, q")
    s.sendall((str(p) + "\n").encode())
    s.sendall((str(q) + "\n").encode())

    # Read flag
    s.settimeout(10)
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
    host = "archive.cryptohack.org"
    port = 45400
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    main(host, port)
