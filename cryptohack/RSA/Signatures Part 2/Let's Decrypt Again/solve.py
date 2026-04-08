#!/usr/bin/env python3
"""
Let's Decrypt Again - CryptoHack RSA Signatures Part 2

Attack: We control N (composite) and e (per claim). SIGNATURE is fixed.
For each claim i: pow(SIGNATURE, e_i, N) == emsa_pkcs1_v15.encode(msg_i + suffix, 96)

Strategy using N = p^2 (smooth prime squared):
  1. Get SIGNATURE from server
  2. Generate smooth prime p (~385 bits) where SIGNATURE is a primitive root mod p and p^2
  3. Set pubkey N = p^2, get suffix
  4. For each claim, craft msg matching pattern + suffix
  5. Compute digest_i = bytes_to_long(emsa_pkcs1_v15.encode(msg_i, 96))
  6. Compute discrete log e_i: SIGNATURE^e_i = digest_i mod p^2
     - dlog mod p via Pohlig-Hellman (p-1 is smooth)
     - lift to mod p^2 via Hensel lifting
  7. Submit each claim, XOR the 3 shares to get the flag
"""

from pwn import *
import json
import hashlib
import random
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime, GCD
from sympy.ntheory import discrete_log as sympy_dlog
from sympy import factorint

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13394

BIT_LENGTH = 768

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def emsa_pkcs1_v15_encode(msg_bytes, emLen):
    """EMSA-PKCS1-v1.5 encoding for SHA-256"""
    der_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    h = hashlib.sha256(msg_bytes).digest()
    T = der_prefix + h
    if emLen < len(T) + 11:
        raise ValueError("intended encoded message length too short")
    PS = b'\xff' * (emLen - len(T) - 3)
    EM = b'\x00\x01' + PS + b'\x00' + T
    return EM

def gen_smooth_prime(bits, attempts=300000):
    """Generate a prime p of given bit length where p-1 is B-smooth."""
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
                    101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199]
    for _ in range(attempts):
        s = 2
        while s.bit_length() < bits - 2:
            p = random.choice(small_primes[:60])
            s *= p
        while s.bit_length() > bits:
            s //= random.choice(small_primes[:30])
        if bits - 2 <= s.bit_length() <= bits:
            if isPrime(s + 1):
                return s + 1
    return None

def is_primitive_root(g, p, factors):
    """Check if g is a primitive root mod p given prime factors of p-1."""
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

def dlog_mod_p_squared(g, h, p, N):
    """
    Compute discrete log: g^e = h mod p^2 (N = p^2).
    Requires g to be a primitive root mod p AND mod p^2.

    Method:
    1. Compute e0 = dlog(h, g, p) mod (p-1)  [Pohlig-Hellman, p-1 smooth]
    2. Hensel lift to find e mod p*(p-1)
    """
    g_mod_p = g % p
    h_mod_p = h % p

    # Step 1: dlog mod p
    e0 = int(sympy_dlog(p, h_mod_p, g_mod_p))

    # Step 2: Hensel lift
    # g^e0 mod p^2 = h0
    h0 = pow(g, e0, N)
    # h / h0 mod p^2 should be 1 mod p
    h_ratio = h * pow(h0, -1, N) % N
    assert h_ratio % p == 1, "Hensel lift failed: h_ratio != 1 mod p"

    # h_ratio = g^(k*(p-1)) mod p^2 for some k in [0, p)
    # g^(p-1) mod p^2 = 1 + t*p (since g^(p-1) = 1 mod p)
    g_pm1 = pow(g, p - 1, N)
    t_g = (g_pm1 - 1) // p
    # h_ratio = 1 + s*p
    s_h = (h_ratio - 1) // p
    # (1 + t_g*p)^k = 1 + k*t_g*p mod p^2
    # k*t_g = s_h mod p
    k = s_h * pow(t_g, -1, p) % p

    e_full = e0 + int(k) * (p - 1)

    # Verify
    assert pow(g, e_full, N) == h, "dlog verification failed"
    return e_full

def btc_address():
    """Generate a valid Bitcoin address (version 0x00)."""
    version = b'\x00'
    payload = b'\x00' * 20
    raw = version + payload
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    raw_full = raw + checksum  # 25 bytes

    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw_full, 'big')
    result = ""
    while n > 0:
        n, r = divmod(n, 58)
        result = alpha[r] + result
    for byte in raw_full:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def solve():
    # Connect and get SIGNATURE first
    if USE_LOCAL:
        r = process(["python3", "13394_b45cc5d677b4748dffa4c6ffd5a6bc67.py"])
    else:
        r = remote(HOST, PORT)

    r.recvline()  # banner

    resp = exchange(r, {"option": "get_signature"})
    SIGNATURE = int(resp["signature"], 16)
    log.info(f"SIGNATURE = {SIGNATURE} ({SIGNATURE.bit_length()} bits)")

    # Generate smooth prime p where SIGNATURE is primitive root mod p and p^2
    log.info("Generating smooth prime p...")
    while True:
        p = gen_smooth_prime(386)
        if p is None:
            continue
        if GCD(SIGNATURE, p) != 1:
            continue
        f = factorint(p - 1)
        if not is_primitive_root(SIGNATURE % p, p, f.keys()):
            continue
        # Check primitive root mod p^2: g^(p-1) != 1 mod p^2
        if pow(SIGNATURE, p - 1, p * p) == 1:
            continue
        break

    N = p * p
    log.success(f"Found p: {p.bit_length()} bits, N = p^2: {N.bit_length()} bits")
    assert not isPrime(N)
    assert N > 2**753, "N too small, digests won't fit"

    # Set pubkey
    resp = exchange(r, {"option": "set_pubkey", "pubkey": hex(N)})
    if "error" in resp:
        log.error(f"set_pubkey error: {resp}")
        r.close()
        return
    suffix = resp["suffix"]
    log.info(f"suffix = {suffix}")

    # Generate messages for each pattern
    msg0 = f"This is a test for a fake signature.{suffix}"
    msg1 = f"My name is Alice and I own CryptoHack.org{suffix}"
    btc_addr = btc_address()
    msg2 = f"Please send all my money to {btc_addr}{suffix}"

    messages = [msg0, msg1, msg2]

    # Process each claim
    shares = []
    for i, msg in enumerate(messages):
        log.info(f"Processing claim {i}: {msg[:50]}...")

        digest = emsa_pkcs1_v15_encode(msg.encode(), BIT_LENGTH // 8)
        digest_int = bytes_to_long(digest)

        if digest_int >= N:
            log.error(f"Digest {i} >= N, need larger p")
            r.close()
            return

        if GCD(digest_int, N) != 1:
            log.error(f"Digest {i} not coprime to N")
            r.close()
            return

        log.info(f"  Computing discrete log...")
        e_i = dlog_mod_p_squared(SIGNATURE % N, digest_int % N, p, N)
        log.success(f"  Claim {i}: e = {e_i} ({e_i.bit_length()} bits)")

        resp = exchange(r, {
            "option": "claim",
            "msg": msg,
            "e": hex(e_i),
            "index": i
        })
        log.info(f"  Response: {resp}")

        if "secret" in resp:
            shares.append(bytes.fromhex(resp["secret"]))
        else:
            log.error(f"Claim {i} failed: {resp}")
            r.close()
            return

    r.close()

    # XOR all shares to get flag
    flag = shares[0]
    for s in shares[1:]:
        flag = xor(flag, s)
    print(f"Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
