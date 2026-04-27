"""
broken oracle (HackTM CTF 2023) — solver

Vulnerability:
  The server implements Williams' Rabin-with-reciprocal (M3) and uses solve_quad
  to find roots of x^2 - r*x + c mod p via the polynomial-based formula
  x^((p-1)/2) mod (x^2 - r*x + c) over GF(p).

  When the discriminant r^2 - 4c is a quadratic non-residue mod p (or mod q),
  the polynomial x^2 - r*x + c is IRREDUCIBLE over GF(p). solve_quad still
  returns "roots" a1, a2 with a1 + a2 = r mod p, but a1*a2 != c mod p — they
  are bogus values, not roots.

  The server then runs decrypt(enc), which uses CRT to glue (a1 or a2 mod p)
  with the valid mod-q root (or vice versa). The "decrypted" m' is wrong:
    m' mod p ∈ {bogus a1, bogus a2}      (when bug fires mod p)
    m' mod q = a valid quadratic root    (when no bug mod q)

  Re-encrypting m' yields r_new with:
    r_new ≡ r_in (mod q)        ← agrees on the good side
    r_new ≢ r_in (mod p) in general

  So gcd(r_new - r_in, n) is divisible by q (when bug only mod p). With many
  random queries we collect multiples of p and multiples of q. Pairwise gcd
  recovers p and q.

  Then to recover c: pick a query r_in that triggers the mod-p bug, vary
  (s, t) in {±1} × {0,1}. The server's decrypt picks different (a1 or a2)
  mod p across these queries, giving multiple distinct r_new mod p values.
  Each satisfies r_new ≡ a_i + c*a_i^{-1} (mod p) with a1 + a2 = r_in (mod p).
  Two distinct r_new mod p values give a 2-equation system for (a1, c) mod p,
  solved as:
    a1 = r_in*(rn2 - r_in) / (rn1 + rn2 - 2*r_in)   (mod p)
    c  = rn1*a1 - a1^2                              (mod p)
  Same trick mod q. CRT to get c mod n.

  With p, q, c known, decrypt the flag using a correct quadratic-root formula
  (Tonelli-Shanks, simplified since p, q ≡ 3 mod 4: sqrt(x) = x^((p+1)/4)).

Steps:
  1. Connect, parse enc_flag.
  2. Send ~60 random (r, s, t) queries; collect (r_in, r_new) diffs.
  3. Pairwise gcd → primes p, q (each ~1024 bits).
  4. For each prime P, find a "bug mod P" query, send 4 (s,t) variants, recover c mod P.
  5. CRT → c. Decrypt flag.
"""
import sys
import socket
import random
from math import gcd
import gmpy2
from Crypto.Util.number import long_to_bytes


HOST = "archive.cryptohack.org"
PORT = 56048
PBITS = 1024  # known from problem statement


# ---- networking ----
class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=30)
        self.buf = b""
    def recv_until(self, marker):
        while marker not in self.buf:
            chunk = self.s.recv(8192)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out
    def send_line(self, line):
        if isinstance(line, str):
            line = line.encode()
        self.s.sendall(line + b"\n")
    def close(self):
        try: self.s.close()
        except: pass


def parse_enc(text):
    # text contains: "r = ...\ns = ...\nt = ..."
    rr = ss = tt = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("r ="):
            rr = int(line.split("=", 1)[1].strip())
        elif line.startswith("s ="):
            ss = int(line.split("=", 1)[1].strip())
        elif line.startswith("t ="):
            tt = int(line.split("=", 1)[1].strip())
    return rr, ss, tt


def main():
    sk = Sock(HOST, PORT)
    # read banner up to first prompt
    pre = sk.recv_until(b"r, s, t = ").decode(errors="ignore")
    print(pre)
    r0, s0, t0 = parse_enc(pre)
    if r0 is None:
        print("Failed to parse encrypted flag")
        return
    print(f"[*] enc_flag.r = {r0}")
    print(f"[*] enc_flag.s = {s0}, enc_flag.t = {t0}")

    def query(r, s, t):
        sk.send_line(f"{r}, {s}, {t}")
        # response: either "decrypt(encrypt(input)):\nr = ..\ns = ..\nt = ..\nr, s, t = "
        # or "Something wrong...\nr, s, t = "
        data = sk.recv_until(b"r, s, t = ").decode(errors="ignore")
        if "Something wrong" in data:
            return None
        return parse_enc(data)

    # Phase 1: collect diffs
    UPPER = 1 << (2 * PBITS - 5)
    queries_data = []
    diffs = []
    NUM_Q = 80
    rng = random.Random(0xC0DE)
    print(f"[*] Phase 1: sending {NUM_Q} random queries...")
    for i in range(NUM_Q):
        r_in = rng.randint(1, UPPER)
        s_in = rng.choice([1, -1])
        t_in = rng.choice([0, 1])
        out = query(r_in, s_in, t_in)
        if out is None:
            continue
        r_new, s_new, t_new = out
        d = r_new - r_in
        queries_data.append((r_in, s_in, t_in, r_new, s_new, t_new, d))
        if d != 0:
            diffs.append(d)
        if (i+1) % 20 == 0:
            print(f"   {i+1}/{NUM_Q}: ok={len(queries_data)}, nonzero diffs={len(diffs)}")
    print(f"[*] total queries: {NUM_Q}, successful: {len(queries_data)}, nonzero diffs: {len(diffs)}")

    # Phase 2: factor n via gcd
    candidates = set()
    for i in range(len(diffs)):
        for j in range(i+1, len(diffs)):
            g = int(gcd(abs(diffs[i]), abs(diffs[j])))
            if g.bit_length() >= PBITS - 5 and g.bit_length() <= PBITS + 5:
                candidates.add(g)
    primes = sorted([cc for cc in candidates if gmpy2.is_prime(cc)])
    print(f"[*] candidate primes count: {len(primes)}")
    distinct = []
    for cc in primes:
        if not any(g % cc == 0 or cc % g == 0 for g in distinct):
            distinct.append(cc)
    primes = distinct
    if len(primes) < 2:
        print("[!] failed to recover both primes; primes =", primes)
        sk.close()
        return
    p_rec, q_rec = primes[0], primes[1]
    n_rec = p_rec * q_rec
    print(f"[*] p, q recovered ({p_rec.bit_length()}, {q_rec.bit_length()} bits)")
    print(f"[*] n = {n_rec.bit_length()} bits")

    # Phase 3: recover c mod p and c mod q
    def recover_c_mod_P(P, other):
        # Find a r_in from queries where d != 0 and (d % other == 0) and (d % P != 0)
        bug_mod_P_only = [q for q in queries_data if q[6] != 0 and (q[6] % other == 0) and (q[6] % P != 0)]
        print(f"[*]  bug-mod-P-only queries available: {len(bug_mod_P_only)} for P={P.bit_length()}b")
        for entry in bug_mod_P_only[:8]:
            r_in = entry[0]
            r_new_modP_set = set()
            r_new_modP_set.add(entry[3] % P)
            for s in [1, -1]:
                for t in [0, 1]:
                    out = query(r_in, s, t)
                    if out is None:
                        continue
                    r_new, _, _ = out
                    r_new_modP_set.add(r_new % P)
            uniq = list(r_new_modP_set)
            if len(uniq) >= 2:
                # Try pairs
                for ii in range(len(uniq)):
                    for jj in range(ii+1, len(uniq)):
                        rn1, rn2 = uniq[ii], uniq[jj]
                        den = (rn1 + rn2 - 2*r_in) % P
                        if den == 0:
                            continue
                        num = (r_in * (rn2 - r_in)) % P
                        a1 = num * pow(den, -1, P) % P
                        a2 = (r_in - a1) % P
                        if a1 == 0 or a2 == 0:
                            continue
                        c_cand = (rn1*a1 - a1*a1) % P
                        # verify with rn2
                        check = (a2 + c_cand * pow(a2, -1, P)) % P
                        if check == rn2:
                            return c_cand
        return None

    print("[*] Phase 3: recovering c mod p...")
    c_mod_p = recover_c_mod_P(p_rec, q_rec)
    print(f"   c mod p: {'OK' if c_mod_p else 'FAILED'}")
    print("[*] Phase 3: recovering c mod q...")
    c_mod_q = recover_c_mod_P(q_rec, p_rec)
    print(f"   c mod q: {'OK' if c_mod_q else 'FAILED'}")
    if c_mod_p is None or c_mod_q is None:
        # could try more random queries before giving up
        print("[!] need more queries; aborting")
        sk.close()
        return

    def crt2(r1, n1, r2, n2):
        g, x, y = gmpy2.gcdext(n1, n2)
        return int((n1*x*r2 + n2*y*r1) % (n1*n2))

    c_rec = crt2(c_mod_p, p_rec, c_mod_q, q_rec)
    print(f"[*] c recovered ({c_rec.bit_length()} bits)")

    # Phase 4: decrypt flag
    # x^2 - r0*x + c_rec ≡ 0 mod p_rec / q_rec. Both ≡ 3 mod 4 → sqrt(x) = x^((p+1)/4) when QR
    def sqrt_mod_p3mod4(x, p):
        x = x % p
        return pow(x, (p+1)//4, p)

    def quad_roots(r, c_, P):
        disc = (r*r - 4*c_) % P
        if pow(disc, (P-1)//2, P) != 1:
            return None
        sd = sqrt_mod_p3mod4(disc, P)
        inv2 = pow(2, -1, P)
        return ((r + sd) * inv2 % P, (r - sd) * inv2 % P)

    mps = quad_roots(r0, c_rec, p_rec)
    mqs = quad_roots(r0, c_rec, q_rec)
    if mps is None or mqs is None:
        print("[!] flag's discriminant not QR — should not happen for valid encryption")
        sk.close()
        return

    candidates_m = []
    for mp in mps:
        for mq in mqs:
            m = crt2(mp, p_rec, mq, q_rec)
            if int(gmpy2.jacobi(m, n_rec)) == s0:
                candidates_m.append(m)
    if len(candidates_m) != 2:
        print(f"[!] expected 2 candidates, got {len(candidates_m)}")
        sk.close()
        return
    m1, m2 = max(candidates_m), min(candidates_m)
    m = m1 if t0 == 1 else m2
    flag_bytes = long_to_bytes(m)
    print(f"[*] recovered m bytes (showing): {flag_bytes[:80]}")
    # locate "HackTM{" or "TM{" in bytes
    for marker in (b"HackTM{", b"flag{", b"FLAG{"):
        idx = flag_bytes.find(marker)
        if idx >= 0:
            end = flag_bytes.find(b"}", idx)
            if end >= 0:
                print(f"[FLAG] {flag_bytes[idx:end+1].decode()}")
                break
    else:
        print(f"[*] full m: {flag_bytes}")

    sk.close()


if __name__ == "__main__":
    main()
