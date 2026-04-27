"""
Vulnerability: NIST P-256 ECDH server doesn't validate that ECDH input lies on
the curve. `Point.__add__/double` only use `p, a` (not `b`), so scalar mul
`(x, y) * d` runs in the group of the alternative curve E_b' : y^2 = x^3 - 3x + b'
where b' = y^2 - x^3 + 3x mod p. With smooth-order alt curves we recover d via PH+CRT.

Crash gotchas (server uses naive recursive Point.__mul__ + Point.double):
  - q = 2: order-2 point has y = 0, double() does pow(0, -1, p) → "base is not invertible".
  - d ≡ 0 (mod q): S = d*Q = INFINITY → point_to_bytes(S) hits S.x = None.
Both crash the connection, killing the round. We:
  - never use q = 2 points
  - order queries large-q first (less likely d ≡ 0); if a query crashes mid-run,
    abort and reconnect (new d, restart). With q ≥ 13 the per-q crash prob is
    sum 1/q ≈ 0.27, so ~76% of connections succeed in one shot.

After enough residues, CRT to recover d mod M; if M ≥ n, d uniquely determined.
ElGamal: send option 2 → (C1, C2) where C1 = r*G, C2 = enc(r*P, flag); decrypt
with r*P = d*C1 (since P = d*G).
"""
import json
import os
import re
import sys
import time
from pwn import remote, context

import sympy

p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a = -3
b_real = 41058363725152142129326129780047268409114441015993725554835256314039467401291
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109

QUOTES = [
    b"Konpeko, konpeko, konpeko! Hololive san-kisei no Usada Pekora-peko! domo, domo!",
    b"Bun bun cha! Bun bun cha!",
    b"kitira!",
    b"usopeko deshou",
    b"HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x93HA\xe2\x86\x93HA\xe2\x86\x93",
    b"HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x91HA\xe2\x86\x91",
    b"it's me pekora!",
    b"ok peko",
]

INF = ("INF",)


def ec_add(P, Q, b):
    if P == INF:
        return Q
    if Q == INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return INF
        l = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        l = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)


def ec_mul(P, k, b):
    if k == 0:
        return INF
    if k < 0:
        return ec_mul((P[0], (-P[1]) % p), -k, b)
    R = INF
    Q = P
    while k:
        if k & 1:
            R = ec_add(R, Q, b)
        Q = ec_add(Q, Q, b)
        k >>= 1
    return R


def on_curve(x, y, b):
    return (y * y - x * x * x - a * x - b) % p == 0


def bsgs(P, S, q, b):
    m = int(sympy.sqrt(q)) + 1
    table = {}
    cur = INF
    for j in range(m):
        key = "INF" if cur == INF else cur[0]
        if key not in table:
            table[key] = j
        cur = ec_add(cur, P, b)
    mP = ec_mul(P, m, b)
    inv_mP = (mP[0], (-mP[1]) % p) if mP != INF else INF
    cur = S
    for i in range(m + 1):
        key = "INF" if cur == INF else cur[0]
        if key in table:
            j = table[key]
            k = (i * m + j) % q
            if ec_mul(P, k, b) == S:
                return k
        cur = ec_add(cur, inv_mP, b)
    raise ValueError("BSGS failed")


def parse_pubkey(line):
    m = re.search(rb"\((\d+),\s*(\d+)\)", line)
    return int(m.group(1)), int(m.group(2))


def query_dh(io, x, y, timeout=5):
    """Send (x, y); return ciphertext. Raises if server crashed (kusa peko)."""
    io.recvuntil(b"> ", timeout=timeout)
    io.sendline(b"1")
    io.recvuntil(b"x: ", timeout=timeout)
    io.sendline(str(x).encode())
    io.recvuntil(b"y: ", timeout=timeout)
    io.sendline(str(y).encode())
    line = io.recvline(timeout=timeout).strip()
    if b"kusa" in line or not line or line.startswith(b"<"):
        raise RuntimeError(f"server crashed: {line!r}")
    try:
        return bytes.fromhex(line.decode())
    except Exception:
        raise RuntimeError(f"non-hex response: {line!r}")


def query_flag(io):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    c1_hex = io.recvline().strip().decode()
    c2_hex = io.recvline().strip().decode()
    C1 = bytes.fromhex(c1_hex)
    C2 = bytes.fromhex(c2_hex)
    C1x = int.from_bytes(C1[:32], "big")
    C1y = int.from_bytes(C1[32:], "big")
    return (C1x, C1y), C2


def identify_S(c, b_aux):
    for q_str in QUOTES:
        padded = q_str[:64].ljust(64, b"\0")
        key = bytes(x ^ y for x, y in zip(c, padded))
        Sx = int.from_bytes(key[:32], "big")
        Sy = int.from_bytes(key[32:], "big")
        if on_curve(Sx, Sy, b_aux):
            return (Sx, Sy), q_str
    return None, None


def crt(rs):
    cur_r, cur_m = 0, 1
    for r, m in rs:
        g = sympy.gcd(cur_m, m)
        if (r - cur_r) % g != 0:
            raise ValueError("CRT incompatible")
        lcm = cur_m * m // g
        rhs = (r - cur_r) % m
        a_div = (cur_m // g)
        rhs_div = rhs // g
        m_div = m // g
        t = (rhs_div * pow(a_div, -1, m_div)) % m_div
        cur_r = (cur_r + cur_m * t) % lcm
        cur_m = lcm
    return cur_r, cur_m


def attempt_attack(chosen, host, port):
    """One connection attempt: returns (residues, M, Px, Py, io) on enough info, else None."""
    io = remote(host, port)
    io.recvuntil(b"public key: ")
    line = io.recvline()
    Px, Py = parse_pubkey(line)
    print(f"  P = ({Px}, {Py})")

    residues = []
    M = 1
    for (q, bp, x, y) in chosen:
        try:
            c = query_dh(io, x, y)
        except Exception as e:
            print(f"  q={q} bp={bp}: aborted ({e})")
            io.close()
            return None
        S, quote = identify_S(c, bp)
        if S is None:
            print(f"  q={q} bp={bp}: identify failed; trying once more")
            try:
                c = query_dh(io, x, y)
                S, quote = identify_S(c, bp)
            except Exception:
                io.close()
                return None
            if S is None:
                print(f"    skip {q}")
                continue
        k = bsgs((x, y), S, q, bp)
        assert ec_mul((x, y), k, bp) == S
        residues.append((k, q))
        M *= q
        print(f"  q={q} bp={bp}: d ≡ {k} (mod {q})  M_bits={M.bit_length()}")
        if M > n:
            return residues, M, Px, Py, io
    if M > n:
        return residues, M, Px, Py, io
    io.close()
    return None


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "curves.json")) as f:
        data = json.load(f)
    items = list(data.items())
    # Largest q first; q=2 is unsafe (server crashes on order-2 doubling).
    items.sort(key=lambda kv: int(kv[0]), reverse=True)
    chosen = [(int(q), bp, x, y) for q, (bp, x, y) in items if int(q) != 2]
    total_M = 1
    for q, _, _, _ in chosen:
        total_M *= q
    print(f"Have {len(chosen)} primes, max M_bits = {total_M.bit_length()}")
    assert total_M > n, "not enough primes to cover n"

    context.log_level = "warning"
    HOST, PORT = "archive.cryptohack.org", 45328

    for attempt in range(10):
        print(f"\n[attempt {attempt+1}]")
        result = attempt_attack(chosen, HOST, PORT)
        if result is not None:
            break
    else:
        raise RuntimeError("all attempts failed")

    residues, M, Px, Py, io = result
    d_mod, M_crt = crt(residues)
    assert M_crt == M, f"M mismatch {M_crt} vs {M}"
    print(f"\nd_mod = {d_mod}")
    print(f"M_bits = {M.bit_length()}")
    d = d_mod % n

    Gp = (Gx, Gy)
    Pp = ec_mul(Gp, d, b_real)
    assert Pp == (Px, Py), f"d verification failed: got {Pp}"
    print(f"d = {d} (verified d*G == P)")

    C1, C2 = query_flag(io)
    print(f"C1 = {C1}")
    print(f"C2 = {C2.hex()}")
    rP = ec_mul(C1, d, b_real)
    assert rP != INF
    key = rP[0].to_bytes(32, "big") + rP[1].to_bytes(32, "big")
    flag = bytes(a ^ b for a, b in zip(C2, key))
    print(f"FLAG: {flag}")

    io.close()


if __name__ == "__main__":
    main()
