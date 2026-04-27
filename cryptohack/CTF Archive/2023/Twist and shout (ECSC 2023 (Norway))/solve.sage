"""
Twist and shout (ECSC 2023 Norway) — quadratic-twist attack on x-only ladder.

Vulnerability:
- The server exposes oracle `shout(x, d) = x([d] P)` using an XZ Montgomery ladder
  on E: y^2 = x^3 + x + 1494 over F_q, q = 2^128 - 159.
- The XZ ladder formulas only depend on (a, b), not on whether the point is on E or
  on its quadratic twist E'. The server never validates that x is on E.
- E has prime order n. But the twist E' has order T = 2(q+1) - n which is fully smooth:
    T = 3 * 79 * 644899 * 1283505703 * 19385376821 * 89480282251 (~ 2^128).
- For each prime r | T, send the x-coordinate of a twist point P_r of order r.
  The server returns x([d mod r] P_r); solve DLP in subgroup of order r → d mod r
  (up to sign because x-only loses sign).
- CRT all residues with sign combinations. d_real < 2^128 ≈ M, so a single CRT
  candidate matches; check ASCII-printability to pick the flag content.

Quirk: when [d] P_r = O, ladder returns Z = 0 and `pow(0, -1, q)` raises and
crashes the connection. We treat such response as `d ≡ 0 (mod r)`. We reconnect
once per query.

Flag: ECSC{7w1st_&&_sh0ut!}
"""
from itertools import product
from pwn import remote, context
context.log_level = 'error'

q = 2**128 - 159
a = 1
b = 1494
n = 340282366920938463465004184633952524077
T = 2*(q+1) - n
factors = [3, 79, 644899, 1283505703, 19385376821, 89480282251]

F = GF(q)
E = EllipticCurve(F, [a, b])
assert E.order() == n

# Quadratic twist via non-residue d=5
nr = F(5)
assert not nr.is_square()
a_t = a * nr**2
b_t = b * nr**3
Et = EllipticCurve(F, [a_t, b_t])
assert Et.order() == T

# Generator on twist
G = Et.gen(0)
assert G.order() == T

def query_server(x_or):
    """One-shot query; returns int response, or None if server crashed (Q=O)."""
    r = remote('archive.cryptohack.org', 11718)
    try:
        r.recvuntil(b'x-coordinate: ')
        r.sendline(str(int(x_or)).encode())
        line = r.recvline(timeout=10).strip()
        if b'Traceback' in line:
            return None
        return int(line)
    finally:
        r.close()

residues = []
for r_prime in factors:
    P_r = (T // r_prime) * G
    assert P_r.order() == r_prime
    Xt = P_r[0]
    # Map x_Et to oracle representation: x_oracle = X_Et / nr (mod q)
    # because the twist E' : nr * y^2 = x^3 + a*x + b corresponds to Et via X_Et = nr * x_E'
    x_oracle = ZZ(Xt / nr) % q
    print(f"Querying r={r_prime}, x_oracle={x_oracle}")
    out = query_server(x_oracle)
    if out is None:
        print(f"  -> identity, d mod {r_prime} = 0")
        residues.append((r_prime, 0))
        continue
    # Map back: X_Q on Et = out * nr (mod q)
    X_Q = (out * int(nr)) % q
    rhs = (int(X_Q)**3 + int(a_t) * int(X_Q) + int(b_t)) % q
    Y_Q = F(rhs).sqrt()
    Q_pt = Et(X_Q, Y_Q)
    k = discrete_log(Q_pt, P_r, ord=r_prime, operation='+')
    print(f"  -> d mod {r_prime} = {k} (or {(-k) % r_prime})")
    residues.append((r_prime, int(k)))

# CRT enumerating sign combos
combos = []
def expand(idx, choices):
    if idx == len(residues):
        combos.append(list(choices))
        return
    r_p, k = residues[idx]
    if k == 0 or 2*k == r_p:
        expand(idx+1, choices + [k])
    else:
        expand(idx+1, choices + [k])
        expand(idx+1, choices + [(-k) % r_p])
expand(0, [])

mods = [m for m,_ in residues]
M = 1
for m in mods: M *= m

# Try each combo; flag content is ASCII printable, length 8..32
import string
PRINTABLE = set(string.printable.encode()) - set(b'\r\x0b\x0c')
for combo in combos:
    cand = CRT_list(combo, mods)
    # d < 2^128 so cand IS d directly
    for L in range(4, 17):
        if cand.bit_length() > 8*L: continue
        if cand < 256**(L-1) and L > 1: continue
        try:
            s = int(cand).to_bytes(L, 'big')
        except OverflowError:
            continue
        if all(c in PRINTABLE for c in s):
            decoded = s.decode('latin1')
            print(f"FLAG candidate: ECSC{{{decoded}}}")
