"""Authenticator — Firebird Internal CTF 2022

Protocol: 6-char alphanumeric password (random.sample → 62P6 ≈ 2^35.37 entropy).
We send challenge_client, server returns response_server = blake3(pw || "HANDSHAKE_FROM_SERVER" || chal_c)
and challenge_server. We must reply response_client = blake3(pw || "HANDSHAKE_FROM_CLIENT" || chal_s)
within 10 s. Password unknown.

Strategy: offline precompute hashes for all passwords whose FIRST CHAR = 'a'
with CHAL_C fixed = 16 zero bytes. 714M candidates, stored as 61 sorted chunks
(by 2nd char) on disk. Each connection:
  1. Send chal_c = zeros
  2. Receive RS, chal_s
  3. Binary-search RS prefix in chunks. If any full hash matches → pw.
  4. If hit: compute RC, send, get flag.
  5. Else: reconnect. Geometric mean = 62 attempts (~1 min).
"""
from pwn import remote, context
from blake3 import blake3
import numpy as np
import sys
import time

context.log_level = 'error'

LABEL_S = b'HANDSHAKE_FROM_SERVER'
LABEL_C = b'HANDSHAKE_FROM_CLIENT'
CHAL_C = b'\x00' * 16
DTYPE = np.dtype([('h', '<u4'), ('pw', 'S6')])
TABLE_DIR = 'D:/auth_table'
HOST = 'archive.cryptohack.org'
PORT = 40156


def load_tables():
    """Memory-map 61 sorted chunk files (~7.1 GB total)."""
    return [np.memmap(f'{TABLE_DIR}/chunk_{i:02d}.bin', dtype=DTYPE, mode='r') for i in range(61)]


def lookup(chunks, rs):
    """Find pw s.t. blake3(pw || LABEL_S || CHAL_C) == rs."""
    h4 = int.from_bytes(rs[:4], 'little')
    for chunk in chunks:
        hs = chunk['h']
        idx = int(np.searchsorted(hs, h4))
        while idx < len(chunk) and hs[idx] == h4:
            pw = bytes(chunk['pw'][idx])
            full = blake3(pw + LABEL_S + CHAL_C).digest()
            if full == rs:
                return pw
            idx += 1
    return None


def one_attempt(chunks):
    r = remote(HOST, PORT, timeout=10)
    try:
        r.sendlineafter(b'challenge_client = ', CHAL_C.hex().encode())
        l1 = r.recvline().strip().decode()
        l2 = r.recvline().strip().decode()
        rs = bytes.fromhex(l1.split('= ')[1])
        cs = bytes.fromhex(l2.split('= ')[1])
        pw = lookup(chunks, rs)
        if pw is None:
            r.close()
            return None
        rc = blake3(pw + LABEL_C + cs).digest()
        r.sendlineafter(b'response_client = ', rc.hex().encode())
        out = r.recvall(timeout=3).decode(errors='replace')
        r.close()
        return pw, out
    except Exception:
        r.close()
        raise


def main():
    chunks = load_tables()
    total = sum(len(c) for c in chunks)
    print(f'[+] Loaded {total:,} entries across {len(chunks)} chunks')

    t0 = time.time()
    for attempt in range(1, 400):
        try:
            res = one_attempt(chunks)
        except Exception as e:
            print(f'[{attempt:3d}] conn err: {e}')
            continue
        if res is None:
            if attempt % 10 == 0:
                elapsed = time.time() - t0
                print(f'[{attempt:3d}] miss (elapsed {elapsed:.1f}s)')
            continue
        pw, out = res
        elapsed = time.time() - t0
        print(f'\n[{attempt:3d}] HIT after {elapsed:.1f}s')
        print(f'    pw = {pw}')
        print(f'    server output:\n{out}')
        return


if __name__ == '__main__':
    main()
