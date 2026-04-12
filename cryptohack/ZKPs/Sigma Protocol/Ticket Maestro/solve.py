"""
Ticket Maestro (200pts) - CTF Archive
archive.cryptohack.org:26896

Attack: Groth16 proof re-randomization.

For any valid Groth16 proof (A, B, C) and scalar λ:
  A' = λ^{-1} · A  (G1 scalar mult)
  B' = λ · B       (G2 scalar mult)
  C' = C           (unchanged)
Then e(A', B') = e(λ^{-1}A, λB) = e(A, B) by bilinearity,
so (A', B', C') is also a valid proof.

Different proof bytes → different blake2 ticket-ID → redeemed independently.

Economics:
  BALANCE          = 10
  COST_OF_FLAG     = 20
  COST_OF_TICKET   = 2
  VALUE_OF_TICKET  = 1

Plan:
  1. Buy 1 ticket  → balance = 8
  2. Redeem original + 12 re-randomizations → balance = 8 + 13 = 21 ≥ 20
  3. Buy flag

Serialization: arkworks compressed format.
  G1 (32 bytes, LE): bit7 of byte[31] = POSITIVE_Y (1 iff y ≤ (p-1)/2), bit6 = INFINITY
  G2 (64 bytes = c0‖c1, each 32 LE): bit7/bit6 of c1[31] = same flags
    IMPORTANT: only top 2 bits are flags; mask with 0x3F not 0x1F when decompressing.
"""

import socket
import json
from py_ecc.bn128 import (
    G1, G2, add, multiply,
    field_modulus as p, FQ2, FQ, b2, curve_order,
)
from py_ecc.bn128 import b as b_g1


# ─── Fp2 square root (BN254, p ≡ 3 mod 4, Fp2 = Fp[i], i²=-1) ──────────────
def fp2_sqrt(x: FQ2):
    a0, a1 = int(x.coeffs[0]), int(x.coeffs[1])
    if a1 == 0:
        r0 = pow(a0, (p + 1) // 4, p)
        if pow(r0, 2, p) == a0:
            return FQ2([r0, 0])
        neg_a0 = (p - a0) % p
        r1 = pow(neg_a0, (p + 1) // 4, p)
        if pow(r1, 2, p) == neg_a0:
            return FQ2([0, r1])
        return None
    norm = (a0 * a0 + a1 * a1) % p
    if pow(norm, (p - 1) // 2, p) != 1:
        return None
    norm_sqrt = pow(norm, (p + 1) // 4, p)
    inv2 = pow(2, p - 2, p)
    for v in [(a0 + norm_sqrt) % p, (a0 - norm_sqrt + p) % p]:
        half = v * inv2 % p
        if pow(half, (p - 1) // 2, p) == 1:
            s = pow(half, (p + 1) // 4, p)
            if s == 0:
                continue
            t = a1 * pow(2 * s, p - 2, p) % p
            for ss, tt in [(s, t), ((p - s) % p, (p - t) % p)]:
                r = FQ2([ss, tt])
                if r * r == x:
                    return r
    return None


# ─── G1 compress / decompress ────────────────────────────────────────────────
def decompress_g1(data: bytes):
    data = bytearray(data)
    is_pos = bool(data[31] & 0x80)   # 1 = y ≤ (p-1)/2
    is_inf = bool(data[31] & 0x40)
    data[31] &= 0x3F                  # clear top 2 flag bits
    if is_inf:
        return None
    x = int.from_bytes(data, 'little')
    y_sq = (pow(x, 3, p) + 3) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if is_pos:
        if y > p // 2:
            y = p - y
    else:
        if y <= p // 2:
            y = p - y
    return (FQ(x), FQ(y))


def compress_g1(point) -> bytes:
    px, py = int(point[0]), int(point[1])
    x_bytes = bytearray(px.to_bytes(32, 'little'))
    if py <= p // 2:
        x_bytes[31] |= 0x80   # POSITIVE_Y
    return bytes(x_bytes)


# ─── G2 compress / decompress ────────────────────────────────────────────────
# ark-serialize G2Affine compressed (64 bytes = c0‖c1, each 32 LE):
#   bit7 of c1[31] = POSITIVE_Y flag
#   bit6 of c1[31] = INFINITY flag
#   (Only top 2 bits are flags; arkworks does NOT use bit5 as a compressed marker)

def decompress_g2(data: bytes):
    c0 = bytearray(data[:32])
    c1 = bytearray(data[32:64])
    fb = c1[31]
    is_pos = bool(fb & 0x80)
    is_inf = bool(fb & 0x40)
    c1[31] &= 0x3F   # IMPORTANT: clear only top 2 flag bits, NOT 3
    if is_inf:
        return None
    xc0 = int.from_bytes(c0, 'little')
    xc1 = int.from_bytes(c1, 'little')
    x = FQ2([xc0, xc1])
    y_sq = x * x * x + b2
    y = fp2_sqrt(y_sq)
    if y is None:
        raise ValueError("G2 sqrt failed")
    yc0, yc1 = int(y.coeffs[0]), int(y.coeffs[1])
    cur_pos = (yc1 <= p // 2) if yc1 != 0 else (yc0 <= p // 2)
    if cur_pos != is_pos:
        y = FQ2([(p - yc0) % p, (p - yc1) % p])
    return (x, y)


def compress_g2(point) -> bytes:
    x, y = point
    xc0, xc1 = int(x.coeffs[0]), int(x.coeffs[1])
    yc0, yc1 = int(y.coeffs[0]), int(y.coeffs[1])
    c0 = bytearray(xc0.to_bytes(32, 'little'))
    c1 = bytearray(xc1.to_bytes(32, 'little'))
    # p < 2^254, so c1[31] < 64 for the field element, top 2 bits are free for flags
    is_pos = (yc1 <= p // 2) if yc1 != 0 else (yc0 <= p // 2)
    if is_pos:
        c1[31] |= 0x80   # POSITIVE_Y
    return bytes(c0 + c1)


# ─── Re-randomization ────────────────────────────────────────────────────────
def rerandomize(A, B, C_bytes: bytes, lam: int) -> str:
    """Re-randomize a Groth16 proof with scalar lam.
    A' = lam^{-1} * A, B' = lam * B, C unchanged.
    All done from the already-decompressed A and B points.
    Returns the new proof as a hex string.
    """
    lam_inv = pow(lam, -1, curve_order)
    A2 = multiply(A, lam_inv)
    B2 = multiply(B, lam)
    return (compress_g1(A2) + compress_g2(B2) + C_bytes).hex()


# ─── Protocol helpers ────────────────────────────────────────────────────────
class Connection:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(60)
        self.s.connect((host, port))
        self.buf = b''

    def recv_until(self, marker):
        if isinstance(marker, str):
            marker = marker.encode()
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Exception("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result

    def recv_line(self):
        return self.recv_until(b'\n').decode().strip()

    def send_line(self, msg):
        if isinstance(msg, str):
            msg = msg.encode()
        self.s.sendall(msg + b'\n')

    def send_recv(self, msg) -> dict:
        self.send_line(msg)
        line = self.recv_line()
        return json.loads(line)


# ─── Main exploit ────────────────────────────────────────────────────────────
HOST, PORT = 'archive.cryptohack.org', 26896


def main():
    print(f"[*] Connecting to {HOST}:{PORT}...")
    conn = Connection(HOST, PORT)

    welcome = conn.recv_line()
    print(f"[*] Server: {welcome}")

    # Check initial balance
    bal = conn.send_recv('"Balance"')
    print(f"[*] Initial balance: {bal}")

    # Buy ONE ticket
    ticket_resp = conn.send_recv('"BuyTicket"')
    proof_hex = ticket_resp['Ticket']['proof']
    print(f"[*] Got ticket proof ({len(proof_hex)//2} bytes): {proof_hex[:32]}...")

    bal = conn.send_recv('"Balance"')
    print(f"[*] Balance after buy: {bal}")

    # Decompress original proof ONCE
    pb = bytes.fromhex(proof_hex)
    A = decompress_g1(pb[:32])
    B = decompress_g2(pb[32:96])
    C_bytes = pb[96:128]
    print("[*] Original proof decompressed successfully")

    # Redeem original proof + 12 re-randomizations = 13 redemptions
    # Starting balance: 8, each redemption adds 1 → 8+13=21 ≥ 20
    lambdas = list(range(1, 20))  # lam=1 means original proof; use many lambdas

    redeemed = 0
    for lam in lambdas:
        if lam == 1:
            variant = proof_hex
        else:
            variant = rerandomize(A, B, C_bytes, lam)

        payload = json.dumps({'Redeem': {'proof': variant}})
        result = conn.send_recv(payload)
        bal_resp = conn.send_recv('"Balance"')
        bal_val = bal_resp.get('Balance', 0)

        if result == 'GoodTicket':
            redeemed += 1
            print(f"[+] lam={lam}: GoodTicket  (balance={bal_val}, redeemed={redeemed})")
        else:
            print(f"[-] lam={lam}: {result} (balance={bal_val})")

        if bal_val >= 20:
            print(f"[*] Balance reached {bal_val}, buying flag...")
            break

    # Buy the flag
    flag_resp = conn.send_recv('"BuyFlag"')
    print(f"\n[!] Flag response: {flag_resp}")

    # Handle various response formats
    if isinstance(flag_resp, dict):
        flag = flag_resp.get('Flag') or flag_resp.get('flag') or str(flag_resp)
    else:
        flag = str(flag_resp)

    if 'crypto{' in flag:
        print(f"\n[+] FLAG: {flag}")
    else:
        print(f"[*] Full response: {flag}")


if __name__ == '__main__':
    main()
