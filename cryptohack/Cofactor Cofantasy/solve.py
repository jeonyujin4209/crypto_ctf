#!/usr/bin/env python3
"""
Cofactor Cofantasy - CryptoHack Challenge Solver

N is a product of 16 safe primes (~200 bits each).
We factor N using phi (Miller-Rabin style splitting), then use
Legendre symbols to distinguish g^r mod N (bit=1) from random (bit=0).

Key insight:
- g is QR mod 5 of the 16 primes and NQR mod 11.
- For bit=1: Legendre(g^r, p_i) = 1 for QR primes, and all NQR primes
  give the same sign (all +1 or all -1 depending on parity of r).
- For bit=0: random value has this exact pattern with probability ~1/2^16.
- Single query per bit is sufficient for reliable identification.
"""

from pwn import *
from math import gcd
import json
import random

# ============================================================
# Challenge parameters
# ============================================================
N = 56135841374488684373258694423292882709478511628224823806418810596720294684253418942704418179091997825551647866062286502441190115027708222460662070779175994701788428003909010382045613207284532791741873673703066633119446610400693458529100429608337219231960657953091738271259191554117313396642763210860060639141073846574854063639566514714132858435468712515314075072939175199679898398182825994936320483610198366472677612791756619011108922142762239138617449089169337289850195216113264566855267751924532728815955224322883877527042705441652709430700299472818705784229370198468215837020914928178388248878021890768324401897370624585349884198333555859109919450686780542004499282760223378846810870449633398616669951505955844529109916358388422428604135236531474213891506793466625402941248015834590154103947822771207939622459156386080305634677080506350249632630514863938445888806223951124355094468682539815309458151531117637927820629042605402188751144912274644498695897277
phi = 56135841374488684373258694423292882709478511628224823806413974550086974518248002462797814062141189227167574137989180030483816863197632033192968896065500768938801786598807509315219962138010136188406833851300860971268861927441791178122071599752664078796430411769850033154303492519678490546174370674967628006608839214466433919286766123091889446305984360469651656535210598491300297553925477655348454404698555949086705347702081589881912691966015661120478477658546912972227759596328813124229023736041312940514530600515818452405627696302497023443025538858283667214796256764291946208723335591637425256171690058543567732003198060253836008672492455078544449442472712365127628629283773126365094146350156810594082935996208856669620333251443999075757034938614748482073575647862178964169142739719302502938881912008485968506720505975584527371889195388169228947911184166286132699532715673539451471005969465570624431658644322366653686517908000327238974943675848531974674382848
g = 986762276114520220801525811758560961667498483061127810099097

# ============================================================
# Factor N using phi (Miller-Rabin style)
# phi = 2^16 * d, so we use a^d mod N and square up, taking GCDs
# ============================================================
def factor_n():
    random.seed(123)
    d = phi >> 16  # phi / 2^16

    divisors = set()
    for trial in range(100):
        a = random.randint(2, N - 2)
        x = pow(a, d, N)
        for i in range(16):
            for val in [x - 1, x + 1]:
                g_val = gcd(val, N)
                if 1 < g_val < N:
                    divisors.add(g_val)
            x = pow(x, 2, N)

    # Extract prime factors by taking GCDs to find smallest divisors
    divs_list = sorted(divisors, key=lambda x: x.bit_length())
    primes = []
    remaining = N
    for d_val in divs_list:
        g_val = gcd(d_val, remaining)
        if 1 < g_val < remaining:
            # Reduce to smallest factor
            changed = True
            while changed:
                changed = False
                for d2 in divs_list:
                    g2 = gcd(g_val, d2)
                    if 1 < g2 < g_val:
                        g_val = g2
                        changed = True
            primes.append(g_val)
            remaining //= g_val
    if remaining > 1:
        primes.append(remaining)
    return primes

print("[*] Factoring N...")
primes = factor_n()
print(f"[+] Found {len(primes)} prime factors")
assert len(primes) == 16, f"Expected 16 factors, got {len(primes)}"

# Verify
prod = 1
for p in primes:
    prod *= p
assert prod == N, "Factoring verification failed!"
phi_check = 1
for p in primes:
    phi_check *= (p - 1)
assert phi_check == phi, "phi verification failed!"
print("[+] Factoring verified: product = N, phi matches")

# ============================================================
# Legendre symbol
# ============================================================
def legendre(a, p):
    val = pow(a, (p - 1) // 2, p)
    return -1 if val == p - 1 else val

# Classify primes by whether g is QR
qr_primes = [p for p in primes if legendre(g, p) == 1]
nqr_primes = [p for p in primes if legendre(g, p) == -1]
print(f"[+] g is QR mod {len(qr_primes)} primes, NQR mod {len(nqr_primes)} primes")

def is_bit_one(val):
    """
    For bit=1: val = g^r mod N
      - Legendre(val, p) = 1 for all QR primes (always)
      - Legendre(val, p) = (-1)^r for all NQR primes (all same sign)
    For bit=0: random value, this pattern holds with prob ~1/2^16
    """
    for p in qr_primes:
        if legendre(val, p) != 1:
            return False
    # All NQR primes must have the same Legendre symbol
    if nqr_primes:
        first = legendre(val, nqr_primes[0])
        for p in nqr_primes[1:]:
            if legendre(val, p) != first:
                return False
    return True

# ============================================================
# Local verification
# ============================================================
print("\n[*] Local verification...")
random.seed(42)
for _ in range(50):
    r = random.randint(2, phi - 1)
    val = pow(g, r, N)
    assert is_bit_one(val), "g^r should always be detected as bit=1!"
print("[+] 50/50 g^r values correctly identified as bit=1")

fp = sum(1 for _ in range(10000) if is_bit_one(random.randint(1, N - 1)))
print(f"[+] False positives for random: {fp}/10000 (expected ~0)")

# ============================================================
# Solve from server
# ============================================================
USE_LOCAL = False
QUERIES_PER_BIT = 2  # 2 queries for extra safety, though 1 is enough

def solve():
    if USE_LOCAL:
        r = remote("localhost", 13398)
    else:
        r = remote("socket.cryptohack.org", 13398)

    # Read banner
    r.recvuntil(b"\n")

    def query_bit(i):
        req = json.dumps({"option": "get_bit", "i": i})
        r.sendline(req.encode())
        resp = r.recvline()
        data = json.loads(resp.decode())
        if "error" in data:
            return None
        return int(data["bit"], 16)

    # Recover flag bit by bit
    # crypto{...} is at least 8 bytes, try up to 64 bytes = 512 bits
    max_bits = 512
    flag_bits = []
    flag_bytes = bytearray()

    print(f"\n[*] Recovering flag ({QUERIES_PER_BIT} queries per bit)...")

    for bit_idx in range(max_bits):
        bit_is_one = True
        for q in range(QUERIES_PER_BIT):
            val = query_bit(bit_idx)
            if val is None:
                # Out of range
                print(f"[*] Bit {bit_idx} out of range, flag is {bit_idx // 8} bytes")
                max_bits = bit_idx
                bit_is_one = None
                break
            if not is_bit_one(val):
                bit_is_one = False
                break  # Definitely 0, no need for more queries

        if bit_is_one is None:
            break

        flag_bits.append(1 if bit_is_one else 0)

        # Assemble byte when we have 8 bits (LSB first per i%8 indexing)
        if len(flag_bits) % 8 == 0:
            byte_val = 0
            for j in range(8):
                byte_val |= flag_bits[-(8 - j)] << j
            flag_bytes.append(byte_val)
            byte_idx = len(flag_bytes)
            if byte_idx % 8 == 0:
                print(f"[*] {byte_idx} bytes: {flag_bytes}")
            if byte_val == ord('}'):
                print(f"[+] Found closing brace at byte {byte_idx}")
                break

    flag = bytes(flag_bytes)
    print(f"\n[+] FLAG = {flag.decode()}")
    r.close()
    return flag

if __name__ == "__main__":
    solve()
