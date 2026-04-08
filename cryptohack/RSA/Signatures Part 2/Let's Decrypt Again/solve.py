#!/usr/bin/env python3
"""
Let's Decrypt Again - CryptoHack RSA Signatures Part 2

Attack: Use N = 41^144 (772 bits). SIGNATURE is a primitive root mod 41.
Group (Z/41^144)* has order 40 * 41^143 = 2^3 * 5 * 41^143 (very smooth).
Pohlig-Hellman + Hensel lifting computes discrete log fast.
"""

from pwn import *
import json
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime, GCD
from sympy.ntheory.modular import crt

USE_LOCAL = False
HOST = "socket.cryptohack.org"
PORT = 13394
BIT_LENGTH = 768

# Precomputed: N = 41^144, group order is very smooth
P_BASE = 41
K_EXP = 144
N_VAL = P_BASE ** K_EXP
PHI_N = (P_BASE - 1) * P_BASE ** (K_EXP - 1)  # 40 * 41^143

def exchange(r, payload):
    r.sendline(json.dumps(payload).encode())
    line = r.recvline().decode().strip()
    idx = line.find('{')
    if idx >= 0:
        line = line[idx:]
    return json.loads(line)

def emsa_encode(msg_bytes, emLen):
    from pkcs1 import emsa_pkcs1_v15
    return emsa_pkcs1_v15.encode(msg_bytes, emLen)

def dlog_prime_power(g, h, p, k, n):
    """Discrete log for the p-part: solve g^x = h mod p^k, x mod p^(k-1).
    Uses iterative p-adic lifting. O(k) modular exponentiations."""
    g_sub = pow(g, p - 1, n)
    h_sub = pow(h, p - 1, n)
    x = 0
    gamma = g_sub
    for i in range(k - 1):
        gx = pow(g_sub, x, n)
        diff = h_sub * pow(gx, -1, n) % n
        c = ((diff - 1) // p**(i + 1)) % p
        a_i = ((gamma - 1) // p**(i + 1)) % p
        if a_i != 0:
            x += (c * pow(a_i, -1, p) % p) * p**i
        gamma = pow(gamma, p, n)
    return x

def dlog_small(g, h, order, n, phi):
    """Brute-force dlog for small prime-power factor of phi."""
    exp = phi // order
    g_sub = pow(g, exp, n)
    h_sub = pow(h, exp, n)
    curr = 1
    for i in range(order):
        if curr == h_sub:
            return i
        curr = curr * g_sub % n
    return 0

def full_dlog(g, h, n):
    """Full discrete log in (Z/41^144)* using Pohlig-Hellman + p-adic lifting."""
    e8 = dlog_small(g, h, 8, n, PHI_N)
    e5 = dlog_small(g, h, 5, n, PHI_N)
    e41 = dlog_prime_power(g, h, P_BASE, K_EXP, n)
    result, _ = crt([8, 5, P_BASE**(K_EXP - 1)], [e8, e5, e41])
    return int(result)

def btc_address():
    """Generate a valid Bitcoin address (version 0x00)."""
    version = b'\x00'
    payload = b'\x00' * 20
    raw = version + payload
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    raw_full = raw + checksum
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw_full, 'big')
    result = ""
    while n > 0:
        n, rem = divmod(n, 58)
        result = alpha[rem] + result
    for byte in raw_full:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def solve():
    r = remote(HOST, PORT)
    r.recvline()  # banner

    resp = exchange(r, {"option": "get_signature"})
    SIGNATURE = int(resp["signature"], 16)
    log.info(f"SIGNATURE = {SIGNATURE} ({SIGNATURE.bit_length()} bits)")

    # Verify SIGNATURE is primitive root mod 41
    g = SIGNATURE % P_BASE
    assert g != 0, "SIGNATURE divisible by 41"
    assert pow(g, 20, P_BASE) != 1 and pow(g, 8, P_BASE) != 1, "Not primitive root mod 41"
    log.success(f"SIGNATURE mod 41 = {g}, primitive root confirmed")

    # Check primitive root mod 41^2
    if pow(SIGNATURE, P_BASE - 1, P_BASE**2) == 1:
        log.error("SIGNATURE^40 ≡ 1 mod 41^2, Hensel lift issue")
        r.close()
        return
    log.success("Primitive root mod 41^2 confirmed")

    # Set pubkey
    resp = exchange(r, {"option": "set_pubkey", "pubkey": hex(N_VAL)})
    if "error" in resp:
        log.error(f"set_pubkey error: {resp}")
        r.close()
        return
    suffix = resp["suffix"]
    log.info(f"suffix = {suffix}")

    # Generate messages
    msg0 = f"This is a test for a fake signature.{suffix}"
    msg1 = f"My name is Alice and I own CryptoHack.org{suffix}"
    btc_addr = btc_address()
    msg2 = f"Please send all my money to {btc_addr}{suffix}"
    messages = [msg0, msg1, msg2]

    shares = []
    for i, msg in enumerate(messages):
        log.info(f"Claim {i}: {msg[:50]}...")

        digest = emsa_encode(msg.encode(), BIT_LENGTH // 8)
        digest_int = bytes_to_long(digest)

        if digest_int >= N_VAL:
            log.error(f"Digest {i} >= N")
            r.close()
            return
        if GCD(digest_int, N_VAL) != 1:
            log.error(f"Digest {i} not coprime to N (divisible by 41)")
            r.close()
            return

        # Compute discrete log: SIGNATURE^e ≡ digest_int mod 41^144
        # Using sympy which handles smooth orders well
        log.info(f"  Computing dlog (p-adic lifting)...")
        e_i = full_dlog(SIGNATURE % N_VAL, digest_int % N_VAL, N_VAL)
        log.success(f"  e = {e_i} ({e_i.bit_length()} bits)")

        # Verify locally
        assert pow(SIGNATURE, e_i, N_VAL) == digest_int % N_VAL, "dlog verification failed!"

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

    flag = shares[0]
    for s in shares[1:]:
        flag = xor(flag, s)
    print(f"Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()
