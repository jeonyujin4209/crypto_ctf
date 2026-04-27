"""
Ticket Maestro (CryptoHack 2024)

Vulnerability: Groth16 proof malleability (re-randomization).
For any valid Groth16 proof (A, B, C):
    A' = lambda^-1 * A,  B' = lambda * B,  C' = C
also verifies (since e(A', B') = e(A, B) by bilinearity).
The server hashes the (digest || proof_bytes) with Blake2 to get the ticket id,
so each fresh lambda yields a *new* spendable ticket from a single original proof.

Economics:
    BALANCE = 10, COST_TICKET = 2, VALUE_TICKET = 1, COST_FLAG = 20
Plan:
    1. BuyTicket once: balance 10 -> 8, get proof bytes
    2. Redeem original + 12 re-randomized proofs: balance 8 + 13 = 21 >= 20
    3. BuyFlag.

Serialization (arkworks 0.3.0, BN254, ark-serialize compressed):
    Proof = A_g1 (32B) || B_g2 (64B) || C_g1 (32B)
    G1 compressed (32B): x in little endian, top 2 bits of last byte are flags
        bit 7 (0x80) = positive_y (1 if y <= (p-1)/2)
        bit 6 (0x40) = infinity
    G2 compressed (64B): c0 (32B LE) || c1 (32B LE), flags in top 2 bits of byte 63
"""

import json
import os
import sys
from pwn import remote, context

from py_ecc.bn128 import (
    G1, G2, multiply, neg, is_on_curve,
    FQ, FQ2, field_modulus, curve_order, b, b2,
)

context.log_level = "warn"

P = field_modulus
HALF = (P - 1) // 2

INFINITY_FLAG = 0x40
POS_Y_FLAG = 0x80


# ---------- Field square root helpers ----------

def fp_sqrt(a):
    """sqrt mod p where p % 4 == 3 (BN254 base field)."""
    assert P % 4 == 3
    r = pow(a, (P + 1) // 4, P)
    if (r * r) % P != a % P:
        return None
    return r


def fp2_sqrt(c0, c1):
    """sqrt in F_p^2 = F_p[u]/(u^2+1).  (a + b u)^2 = (a^2 - b^2) + 2ab u."""
    if c0 == 0 and c1 == 0:
        return (0, 0)
    if c1 == 0:
        r = fp_sqrt(c0)
        if r is not None:
            return (r, 0)
        # c0 is non-residue, sqrt = sqrt(-c0) * u
        r = fp_sqrt((-c0) % P)
        assert r is not None
        return (0, r)
    # General case: norm = c0^2 + c1^2 (since u^2 = -1, so |a+bu|^2 = a^2+b^2)
    norm = (c0 * c0 + c1 * c1) % P
    n_root = fp_sqrt(norm)
    if n_root is None:
        return None
    # We need x, y with x^2 - y^2 = c0,  2xy = c1
    # Let s = sqrt(norm), then x^2 = (c0 + s)/2, y^2 = (s - c0)/2 (or other sign of s)
    inv2 = pow(2, -1, P)
    for s in (n_root, (-n_root) % P):
        x2 = ((c0 + s) * inv2) % P
        x = fp_sqrt(x2)
        if x is None:
            continue
        if x == 0:
            continue
        y = (c1 * pow(2 * x, -1, P)) % P
        # Verify
        if (x * x - y * y) % P == c0 % P and (2 * x * y) % P == c1 % P:
            return (x, y)
    return None


# ---------- Compression / Decompression ----------

def decompress_g1(data: bytes):
    assert len(data) == 32
    last = data[31]
    flags = last & 0xC0
    x_bytes = data[:31] + bytes([last & 0x3F])
    x = int.from_bytes(x_bytes, "little")
    if flags & INFINITY_FLAG:
        return None  # point at infinity
    rhs = (x * x * x + 3) % P  # y^2 = x^3 + 3
    y = fp_sqrt(rhs)
    assert y is not None, "G1 decompress: not on curve"
    pos_y = (flags & POS_Y_FLAG) != 0
    if pos_y and y > HALF:
        y = (-y) % P
    elif (not pos_y) and y <= HALF:
        y = (-y) % P
    return (FQ(x), FQ(y))


def compress_g1(point) -> bytes:
    if point is None:
        out = bytearray(32)
        out[31] |= INFINITY_FLAG
        return bytes(out)
    x = point[0].n
    y = point[1].n
    out = bytearray(x.to_bytes(32, "little"))
    # top 2 bits of x must be 0 since BN254 p < 2^254
    assert out[31] & 0xC0 == 0
    if y <= HALF:
        out[31] |= POS_Y_FLAG
    return bytes(out)


def compress_g2(point) -> bytes:
    if point is None:
        out = bytearray(64)
        out[63] |= INFINITY_FLAG
        return bytes(out)
    x = point[0]
    y = point[1]
    c0 = x.coeffs[0].n
    c1 = x.coeffs[1].n
    out = bytearray(c0.to_bytes(32, "little") + c1.to_bytes(32, "little"))
    assert out[63] & 0xC0 == 0
    y0 = y.coeffs[0].n
    y1 = y.coeffs[1].n
    neg_y0 = (-y0) % P
    neg_y1 = (-y1) % P
    # arkworks PartialOrd derived on (c0, c1) struct -> lex on c0 first
    if y0 != neg_y0:
        positive = y0 > neg_y0
    else:
        positive = y1 > neg_y1
    if positive:
        out[63] |= POS_Y_FLAG
    return bytes(out)


# Override decompress_g2 with a version that returns (x, y) directly using same rule
def decompress_g2(data: bytes):
    assert len(data) == 64
    last = data[63]
    flags = last & 0xC0
    c0 = int.from_bytes(data[:32], "little")
    c1_bytes = data[32:63] + bytes([last & 0x3F])
    c1 = int.from_bytes(c1_bytes, "little")
    if flags & INFINITY_FLAG:
        return None

    def fp2_mul(a, b):
        a0, a1 = a; b0, b1 = b
        return ((a0 * b0 - a1 * b1) % P, (a0 * b1 + a1 * b0) % P)
    def fp2_add(a, b):
        return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)

    x = (c0, c1)
    x3 = fp2_mul(fp2_mul(x, x), x)
    b2c = (b2.coeffs[0].n, b2.coeffs[1].n)
    rhs = fp2_add(x3, b2c)
    sol = fp2_sqrt(rhs[0], rhs[1])
    assert sol is not None, "G2 decompress: y^2 has no sqrt"
    y0, y1 = sol
    neg_y0 = (-y0) % P
    neg_y1 = (-y1) % P
    if y0 != neg_y0:
        positive = y0 > neg_y0
    else:
        positive = y1 > neg_y1
    pos_y_flag = (flags & POS_Y_FLAG) != 0
    if positive != pos_y_flag:
        y0, y1 = neg_y0, neg_y1
    Pt = (FQ2([y0, y1]),)  # placeholder
    return (FQ2([c0, c1]), FQ2([y0, y1]))


# ---------- Server interaction ----------

def parse_proof_bytes(proof_hex: str):
    raw = bytes.fromhex(proof_hex)
    assert len(raw) == 32 + 64 + 32, f"unexpected proof length {len(raw)}"
    A = raw[:32]
    B = raw[32:32 + 64]
    C = raw[32 + 64:]
    return A, B, C


def serialize_proof(A_bytes, B_bytes, C_bytes):
    return (A_bytes + B_bytes + C_bytes).hex()


def rerandomize_proof(A_bytes, B_bytes, C_bytes, lam: int):
    A = decompress_g1(A_bytes)
    B = decompress_g2(B_bytes)
    lam_inv = pow(lam, -1, curve_order)
    A2 = multiply(A, lam_inv)
    B2 = multiply(B, lam)
    return compress_g1(A2), compress_g2(B2), C_bytes


# ---------- Local sanity test ----------

def sanity_self_check():
    # Ensure decompress(compress(P)) == P for a few G1 / G2 points
    for k in [1, 2, 3, 12345, curve_order - 1]:
        P1 = multiply(G1, k)
        c = compress_g1(P1)
        Pd = decompress_g1(c)
        assert Pd[0].n == P1[0].n and Pd[1].n == P1[1].n, f"G1 roundtrip failed k={k}"
        P2 = multiply(G2, k)
        c2 = compress_g2(P2)
        P2d = decompress_g2(c2)
        assert P2d[0].coeffs[0].n == P2[0].coeffs[0].n
        assert P2d[0].coeffs[1].n == P2[0].coeffs[1].n
        assert P2d[1].coeffs[0].n == P2[1].coeffs[0].n
        assert P2d[1].coeffs[1].n == P2[1].coeffs[1].n
    print("[+] Local roundtrip ok", file=sys.stderr)


def main():
    sanity_self_check()

    HOST = os.environ.get("HOST", "archive.cryptohack.org")
    PORT = int(os.environ.get("PORT", "26896"))
    r = remote(HOST, PORT)
    r.recvline()

    def call(req):
        if isinstance(req, str):
            r.sendline(json.dumps(req).encode())
        else:
            r.sendline(json.dumps(req).encode())
        return json.loads(r.recvline().decode())

    bal = call("Balance")
    print(f"[*] start balance: {bal}", file=sys.stderr)

    # 1. Buy a ticket
    resp = call("BuyTicket")
    proof_hex = resp["Ticket"]["proof"]
    print(f"[*] got ticket, len={len(proof_hex)//2}B", file=sys.stderr)

    bal = call("Balance")
    print(f"[*] after buy: {bal}", file=sys.stderr)

    A_b, B_b, C_b = parse_proof_bytes(proof_hex)

    # 2. Redeem original
    resp = call({"Redeem": {"proof": proof_hex}})
    print(f"[*] redeem original: {resp}", file=sys.stderr)
    assert resp == "GoodTicket"

    # 3. Re-randomize and redeem multiple times
    needed = 12  # 8 -> 8+12 = 20
    redeemed = 0
    lam = 2
    while redeemed < needed:
        A2, B2, C2 = rerandomize_proof(A_b, B_b, C_b, lam)
        new_hex = serialize_proof(A2, B2, C2)
        resp = call({"Redeem": {"proof": new_hex}})
        if resp == "GoodTicket":
            redeemed += 1
            print(f"[+] redeem #{redeemed} ok (lam={lam})", file=sys.stderr)
        else:
            print(f"[-] redeem failed lam={lam}: {resp}", file=sys.stderr)
        lam += 1
        if lam > 200:
            break

    bal = call("Balance")
    print(f"[*] balance before flag: {bal}", file=sys.stderr)

    flag_resp = call("BuyFlag")
    print(f"[FLAG] {flag_resp}")
    r.close()


if __name__ == "__main__":
    main()
