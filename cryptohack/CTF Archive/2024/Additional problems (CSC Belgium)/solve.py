"""Solve "Additional problems" (CSC Belgium 2024 / CryptoHack archive).

Vulnerability: DGHV scheme with c = p*q + N*r + m, where p is 128-bit prime
and noise N*r < 2^126. The η-ρ gap is only 2 bits, but the more usable bug is
an OVERFLOW ORACLE: after issuing many add operations, the cumulated ciphertext
T = N*sum(r) + sum(m) can exceed p, and decrypt returns (T - j*p) mod N where
j = floor(T/p) ∈ {0, 1, 2, ...}.

If we set m=1 each time, after k adds the decrypt result is ((k+1) - j*p) mod N.
Diff between consecutive decrypts is +1 (no new overflow) or (1 - p mod N) mod N
(one new overflow). The non-+1 diff value reveals p mod N exactly.

Run for N = each prime in [128, 255], CRT residues to get full p (~184 bits, more
than enough to uniquely determine our 128-bit p), then decrypt the flag chars
that the server gave us at connect time.
"""
from pwn import remote, context
from sympy import isprime
from sympy.ntheory.modular import crt
from collections import Counter
import sys, time

context.log_level = "warn"

HOST, PORT = "archive.cryptohack.org", 21970


def parse_flag_block(io):
    io.recvuntil(b"encrypted our secret flag with it:\n")
    cs = []
    while True:
        line = io.recvline(timeout=5)
        if not line:
            break
        s = line.strip()
        if not s:
            continue
        if not s.lstrip().isdigit() and not all(c in b"0123456789" for c in s.lstrip()):
            # end of block
            break
        try:
            cs.append(int(s))
        except ValueError:
            break
    return cs


def setup_new(io, N, m_byte=1, first=False):
    # On the very first inner-loop iteration, server forces action="new" and
    # skips the menu prompt — go straight to "Choose N: ".
    if not first:
        io.sendlineafter(b"     > ", b"1")
    io.sendlineafter(b"Choose N: ", str(N).encode())
    io.sendlineafter(b"hexadecimal): ", b"%02x" % m_byte)


def add_one(io, m_byte=1):
    io.sendlineafter(b"     > ", b"2")
    io.sendlineafter(b"hexadecimal): ", b"%02x" % m_byte)


def decrypt_now(io):
    io.sendlineafter(b"     > ", b"3")
    io.recvuntil(b"Decrypted message: ")
    line = io.recvline().strip().decode()
    return int(line, 16) if line else 0


def recover_p_mod_N(io, N, K=15, first=False):
    setup_new(io, N, first=first)
    res = [decrypt_now(io)]
    for _ in range(K):
        add_one(io)
        res.append(decrypt_now(io))
    diffs = [(res[i + 1] - res[i]) % N for i in range(len(res) - 1)]
    overflow = [d for d in diffs if d != 1]
    if not overflow:
        return None, res
    most = Counter(overflow).most_common(1)[0][0]
    return (1 - most) % N, res


def main():
    t0 = time.time()
    io = remote(HOST, PORT)
    flag_cs = parse_flag_block(io)
    print(f"[+] flag_len = {len(flag_cs)}, c bits = {flag_cs[0].bit_length() if flag_cs else 0}", flush=True)

    primes = [n for n in range(128, 256) if isprime(n)]
    print(f"[+] using {len(primes)} primes", flush=True)

    mods, rems = [], []
    for i, N in enumerate(primes):
        pm, _ = recover_p_mod_N(io, N, first=(i == 0))
        if pm is None:
            print(f"[-] N={N}: no overflow seen", flush=True)
            continue
        mods.append(N)
        rems.append(pm)
        print(f"[+] N={N}: p mod N = {pm}  (t={time.time()-t0:.1f}s)", flush=True)
        # early stop once modulus exceeds 2^130
        prod = 1
        for m in mods:
            prod *= m
        if prod.bit_length() >= 140:
            print(f"[+] modulus product {prod.bit_length()} bits >= 140, stop early", flush=True)
            break

    val, mod = crt(mods, rems)
    p = int(val)
    print(f"[+] recovered p = {p}", flush=True)
    print(f"[+] p bits = {p.bit_length()}", flush=True)

    # Decrypt flag
    flag = bytes([(c % p) % 128 for c in flag_cs])
    print(f"[+] flag = {flag}", flush=True)
    io.close()


if __name__ == "__main__":
    main()
