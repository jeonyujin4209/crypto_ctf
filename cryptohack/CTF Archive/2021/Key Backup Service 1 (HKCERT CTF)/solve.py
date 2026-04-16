"""
Key Backup Service 1 (HKCERT CTF 2021) — Hastad's Broadcast Attack

Vulnerability:
  E = 17, master_secret is 256 bits, n_i are 1024 bits.
  ms^17 < 2^4352 and product of 5 moduli > 2^5110.
  So 5 ciphertexts + CRT give ms^17 exactly, then take integer 17th root.

Budget (17 calls):
  5 keys × (pkey + send + backup) = 15
  1 extra send on key 5 for exact n via GCD = 1
  1 flag = 1
  Total = 17

n-recovery from 1 send:
  Send m = 2^61. c = m^17 mod n.  m^17 - c = k*n where k ≈ 2^13.
  Test each k for divisibility.  ~1-2 valid candidates per key.
  Key 5 gets exact n via GCD of two sends.
"""
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from gmpy2 import iroot
from math import gcd
from functools import reduce
from itertools import product as cprod

HOST = 'archive.cryptohack.org'
PORT = 4077

# --- Interaction helpers ---
def do_pkey(r):
    r.recvuntil(b'[cmd] ')
    r.sendline(b'pkey')

def do_send(r, m_int):
    r.recvuntil(b'[cmd] ')
    r.sendline(f'send {m_int:x}'.encode())
    return int(r.recvline().strip(), 16)

def do_backup(r):
    r.recvuntil(b'[cmd] ')
    r.sendline(b'backup')
    return int(r.recvline().strip(), 16)

def do_flag(r):
    r.recvuntil(b'[cmd] ')
    r.sendline(b'flag')
    return bytes.fromhex(r.recvline().strip().decode())

# --- n-recovery from single send ---
def find_n_candidates(c_send, c_backup, m_17):
    kn = m_17 - c_send
    if kn <= 0:
        return []
    k_lo = max(1, kn >> 1024)        # n < 2^1024 => k > kn/2^1024
    k_hi = (kn >> 1022) + 2          # n >= 2^1022 => k <= kn/2^1022
    if c_backup > 0:
        k_hi = min(k_hi, kn // c_backup + 1)  # n > c_backup => k < kn/c_backup
    candidates = []
    for k in range(k_lo, k_hi + 1):
        if kn % k == 0:
            n = kn // k
            if n % 2 == 1 and n > c_backup and 1022 <= n.bit_length() <= 1024:
                candidates.append(n)
    return candidates

# --- CRT ---
def crt(residues, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for r_i, m_i in zip(residues, moduli):
        Mi = M // m_i
        yi = pow(Mi, -1, m_i)
        x += r_i * Mi * yi
    return x % M

# === Main ===
r = remote(HOST, PORT)

m1 = 1 << 61       # primary send value
m2 = 3 ** 40       # secondary send for GCD on key 5
m1_17 = m1 ** 17
m2_17 = m2 ** 17

keys = []  # (c_send, c_backup)

# Keys 1-5: pkey + send(m1) + backup = 15 calls
for i in range(5):
    do_pkey(r)
    cs = do_send(r, m1)
    cb = do_backup(r)
    keys.append((cs, cb))
    log.info(f"Key {i+1} collected")

# Extra send on key 5 for GCD (call 16)
c_s5_m2 = do_send(r, m2)

# Flag (call 17)
flag_ct = do_flag(r)
r.close()
log.info(f"Flag ciphertext: {len(flag_ct)} bytes")

# --- Recover n for keys 1-4 via k-enumeration ---
all_key_info = []  # list of [(n, c_backup), ...]

for i in range(4):
    cs, cb = keys[i]
    cands = find_n_candidates(cs, cb, m1_17)
    all_key_info.append([(n, cb) for n in cands])
    log.info(f"Key {i+1}: {len(cands)} n-candidates")

# --- Key 5: exact n via GCD ---
kn5a = m1_17 - keys[4][0]
kn5b = m2_17 - c_s5_m2
n5 = gcd(kn5a, kn5b)
# Clean up small prime factors from gcd(k1, k2)
for p in range(2, 100000):
    while n5 % p == 0 and n5.bit_length() > 1025:
        n5 //= p

if 1022 <= n5.bit_length() <= 1024 and n5 % 2 == 1 and keys[4][1] < n5:
    all_key_info.append([(n5, keys[4][1])])
    log.info(f"Key 5: exact n ({n5.bit_length()} bits)")
else:
    # Fallback to k-enumeration
    cands = find_n_candidates(keys[4][0], keys[4][1], m1_17)
    all_key_info.append([(n, keys[4][1]) for n in cands])
    log.info(f"Key 5: {len(cands)} n-candidates (GCD failed, using fallback)")

# --- Hastad's broadcast attack ---
total = 1
for ki in all_key_info:
    total *= len(ki)
log.info(f"Trying {total} combinations...")

for combo in cprod(*all_key_info):
    ns = [n for n, _ in combo]
    cbs = [cb for _, cb in combo]

    # Pairwise coprime check
    ok = True
    for i in range(5):
        for j in range(i + 1, 5):
            if gcd(ns[i], ns[j]) > 1:
                ok = False
                break
        if not ok:
            break
    if not ok:
        continue

    # CRT
    try:
        C = crt(cbs, ns)
    except Exception:
        continue

    # Perfect 17th root?
    root, is_perfect = iroot(C, 17)
    if is_perfect:
        ms = int(root)
        ms_bytes = ms.to_bytes(32, 'big')
        log.success(f"master_secret = {ms_bytes.hex()}")

        cipher = AES.new(ms_bytes, AES.MODE_CBC, b'\0' * 16)
        flag = unpad(cipher.decrypt(flag_ct), 16)
        log.success(f"Flag: {flag.decode()}")
        break
else:
    log.error("No valid combination found")
