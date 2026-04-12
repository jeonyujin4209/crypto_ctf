"""
Let's Prove It (ZKP Challenges, 120pts) — c = H^2 perfect-square leak

Vulnerability
=============
  fiatShamir():
      p  = getPrime(BITS)          # 1024-bit prime
      y  = pow(g, FLAG, p)
      self.refresh()               # R = Random(os.urandom(8)) — unknown
      v  = R.getrandbits(512)      # v ~ 2^512
      t  = pow(g, v, p)
      c  = sha3_256(t ^ y ^ g)^2  # ← BUG: squared hash, c ~ 2^512
      r  = (v - c*FLAG) % (p-1)

Since FLAG ~ 2^312 (38 bytes + 1 injected non-printable = 39 bytes → 312 bits):
  c * FLAG ~ 2^512 * 2^312 = 2^824
  v        ~ 2^512
  p - 1    ~ 2^1024

  c*FLAG > v, so modular reduction adds exactly one (p-1):
    r = v - c*FLAG + (p-1)
  ⟹ v = r + c*FLAG - (p-1)          (v ≥ 0 because c*FLAG < p-1 ≈ 2^1024)

Rearranging:  FLAG = (v + (p-1) - r) / c

Since v ∈ [0, 2^512) and c ~ 2^512, the interval for FLAG has width:
  2^512 / c ≈ 1

So: FLAG = floor( (p-1-r) / c )  or  +1 — only ~2 candidates per proof!

Getting KNOWN p
===============
  refresh(seed) sets R = Random(nonce + seed).
  The next get_proof calls getPrime using that same R.
  ⟹ We can simulate getPrime(nonce, seed) locally to predict p.

Protocol to gather one known-prime proof
=========================================
  Initial: your_turn=1
  1. get_proof        → your_turn=2  (needed to unlock refresh)
  2. refresh(seed)    → your_turn=0  (R = Random(nonce+seed))
  3. get_proof        → your_turn=1  KNOWN p!
  4. get_proof        → your_turn=2  (discard, needed for next refresh)
  5. refresh(seed2)   → your_turn=0
  6. get_proof        → your_turn=1  KNOWN p (backup)
  ...
  max_turns=12 (only get_proof increments turn), so we have plenty of room.

Decoding
========
  long_to_bytes(FLAG_int)  =  xor_nonce(add_random_nonprintable(FLAG_real), nonce)
  - Undo xor_nonce: XOR bytes[7:-1] with nonce (both 31 bytes)
  - Result is FLAG_real with one non-printable byte inserted at an unknown index
  - Try removing each byte until we see b"crypto{...}"
"""
import json
import random
import re
import socket
import time
import hashlib
import string
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime

HOST = "socket.cryptohack.org"
PORT = 13430
BITS = 2 << 9   # 1024
g    = 2


# ──────────────────────────── network helpers ────────────────────────────────

def recv_all(sock, timeout=4.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            sock.settimeout(0.8)
    except socket.timeout:
        pass
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def parse_first_json(blob):
    for line in blob.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except Exception:
                pass
    return None


# ──────────────────────────── crypto helpers ─────────────────────────────────

def simulate_get_prime(nonce: bytes, seed: bytes, bits: int = BITS) -> int:
    """Reproduce Challenge.getPrime() with R = Random(nonce + seed)."""
    R = random.Random(nonce + seed)
    while True:
        number = R.getrandbits(bits) | 1
        if isPrime(number, randfunc=lambda x: long_to_bytes(R.getrandbits(x))):
            return number


def compute_c(t: int, y: int) -> int:
    """c = sha3_256(t ^ y ^ g)^2  (the squared hash in the source)."""
    h = hashlib.sha3_256(long_to_bytes(t ^ y ^ g)).digest()
    return bytes_to_long(h) ** 2


def undo_xor_nonce(flag_bytes: bytes, nonce: bytes) -> bytes:
    """Reverse xor_nonce: XOR bytes[7:-1] (31 bytes) with nonce (31 bytes)."""
    assert len(nonce) == 31
    start  = flag_bytes[:7]
    end    = flag_bytes[-1:]
    middle = flag_bytes[7:-1]
    assert len(middle) == len(nonce), f"middle len {len(middle)} != nonce len {len(nonce)}"
    return start + bytes(a ^ b for a, b in zip(middle, nonce)) + end


def recover_real_flag(candidate: bytes):
    """
    candidate = add_random_nonprintable(FLAG_real).
    FLAG_real is 38 bytes; candidate is 39 bytes (one non-printable inserted).
    Try removing each byte; return b"crypto{...}" when found.
    """
    for i in range(len(candidate)):
        removed_byte = candidate[i]
        attempt = candidate[:i] + candidate[i+1:]
        if (chr(removed_byte) not in string.printable
                and attempt.startswith(b"crypto{")
                and attempt.endswith(b"}")):
            return attempt
    return None


def solve_for_flag(p: int, c: int, r: int, y: int) -> int | None:
    """
    Given p, c, r, y (where y = g^FLAG mod p):
      v = r + c*FLAG - (p-1)    with  0 <= v < 2^BITS
    => FLAG in [(p-1-r)//c, (p-1-r+2^BITS)//c + 1]
    Width ≈ 2^BITS / c ≈ 1.
    Verify candidate by checking pow(g, cand, p) == y.
    """
    numerator  = (p - 1) - r          # = c*FLAG - v
    flag_low   = numerator // c
    flag_high  = (numerator + 2**BITS) // c + 2

    for cand in range(max(1, flag_low), flag_high + 1):
        v_check = c * cand - numerator
        if v_check < 0 or v_check >= 2**BITS:
            continue
        if pow(g, cand, p) == y:
            return cand
    return None


# ──────────────────────────── main ───────────────────────────────────────────

def main():
    print(f"[*] Connecting to {HOST}:{PORT} ...")
    sock = socket.create_connection((HOST, PORT))
    time.sleep(0.5)

    greeting = recv_all(sock, 2.0)
    print(greeting.strip())

    m = re.search(r"nonce for this instance:\s*([0-9a-fA-F]+)", greeting)
    assert m, f"nonce not found in greeting: {greeting!r}"
    nonce = bytes.fromhex(m.group(1))
    print(f"[*] nonce = {nonce.hex()}  ({len(nonce)} bytes)")
    assert len(nonce) == 31

    # ── Warm-up: get_proof to increment your_turn from 1 to 2 ────────────────
    print("[*] Warm-up get_proof (your_turn: 1 → 2) ...")
    send_json(sock, {"option": "get_proof"})
    warm = parse_first_json(recv_all(sock, 10.0))
    assert warm and "error" not in warm, f"warm-up error: {warm}"
    print(f"    OK")

    # ── Round loop: refresh(seed) → get_proof(known p) → get_proof(discard) ──
    seeds = [bytes([i]) * 8 for i in range(5)]   # at most 5 rounds (3 get_proofs each = 15, but we exit early)
    found_flag = None

    for idx, seed in enumerate(seeds):
        print(f"\n[*] Round {idx}: seed={seed.hex()}")

        # Step A: refresh → sets R = Random(nonce+seed) for next getPrime
        send_json(sock, {"option": "refresh", "seed": seed.hex()})
        ref = parse_first_json(recv_all(sock, 3.0))
        assert ref and "error" not in ref, f"refresh error at round {idx}: {ref}"
        print(f"    refresh OK: {ref.get('msg', ref)}")

        # Step B: simulate getPrime locally (same R)
        print(f"    simulating getPrime(nonce, seed) ...", end=" ", flush=True)
        p_sim = simulate_get_prime(nonce, seed)
        print(f"{p_sim.bit_length()} bits")

        # Step C: get_proof with KNOWN p
        send_json(sock, {"option": "get_proof"})
        proof = parse_first_json(recv_all(sock, 10.0))
        assert proof and "error" not in proof, f"get_proof error at round {idx}: {proof}"

        t_val = proof["t"]
        r_val = proof["r"]
        y_val = proof["y"]
        print(f"    t<p: {t_val < p_sim},  y<p: {y_val < p_sim}")
        assert t_val < p_sim, "p mismatch: t >= p_sim"
        assert y_val < p_sim, "p mismatch: y >= p_sim"

        c_val = compute_c(t_val, y_val)
        print(f"    c={c_val.bit_length()} bits, r={r_val.bit_length()} bits")

        # Step D: solve
        flag_int = solve_for_flag(p_sim, c_val, r_val, y_val)
        if flag_int is not None:
            print(f"    [+] FLAG integer found: {hex(flag_int)[:40]}...")
            found_flag = flag_int
            break
        else:
            print(f"    [!] No FLAG found this round, continuing...")

        # Step E: discard get_proof (your_turn: 1 → 2) for next refresh
        if idx < len(seeds) - 1:
            send_json(sock, {"option": "get_proof"})
            disc = parse_first_json(recv_all(sock, 10.0))
            if disc and "error" not in disc:
                print(f"    discard get_proof OK (your_turn: 1 → 2)")
            else:
                print(f"    [!] discard get_proof: {disc}")

    sock.close()

    if found_flag is None:
        print("[!] Failed to recover FLAG integer")
        return

    print(f"\n[+] FLAG integer = {hex(found_flag)}")
    flag_bytes = long_to_bytes(found_flag)
    print(f"[+] FLAG bytes ({len(flag_bytes)}) = {flag_bytes.hex()}")

    # Pad to 39 bytes if shorter (big-endian, leading zeros)
    if len(flag_bytes) < 39:
        flag_bytes = flag_bytes.rjust(39, b'\x00')
    if len(flag_bytes) != 39:
        print(f"[!] Unexpected length: {len(flag_bytes)} (expected 39)")

    # Undo xor_nonce
    unxored = undo_xor_nonce(flag_bytes, nonce)
    print(f"[+] After undo_xor_nonce = {unxored!r}")

    # Remove injected non-printable byte
    real_flag = recover_real_flag(unxored)
    if real_flag:
        print(f"\n[+] FLAG: {real_flag.decode()}")
    else:
        print("[!] Could not auto-extract flag. Trying all removals:")
        for i in range(len(unxored)):
            attempt = unxored[:i] + unxored[i+1:]
            print(f"    remove[{i:2d}]: {attempt!r}")


if __name__ == "__main__":
    main()
