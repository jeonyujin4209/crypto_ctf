"""Precompute blake3(pw || "HANDSHAKE_FROM_SERVER" || chal_c) for passwords
with fixed first character 'a'. chal_c fixed to 16 zero bytes.

Total: 61*60*59*58*57 = 713,803,680 candidates (~2^29.4).
Output: 61 sorted chunks (one per 2nd char), each 11.7M records.
Record = (hash_prefix_u32_le, pw_6B) = 10 bytes.

Optimization: reuse 43-byte msg bytearray, update only pw bytes in inner loop.
Write results to raw 10B/record buffer, wrap via np.frombuffer, sort by hash prefix.
"""
import multiprocessing as mp
from blake3 import blake3
from itertools import permutations
import numpy as np
import os
import time
import sys

ALPHABET = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
FIRST = ord('a')
LABEL_S = b'HANDSHAKE_FROM_SERVER'
CHAL_C = b'\x00' * 16
REMAINING = bytes(c for c in ALPHABET if c != FIRST)  # 61 chars
OUTDIR = 'D:/auth_table'

DTYPE = np.dtype([('h', '<u4'), ('pw', 'S6')])  # 10 bytes per record


def worker(second_idx):
    second_char = REMAINING[second_idx]
    after_two = bytes(c for c in REMAINING if c != second_char)  # 60 chars
    n = 60 * 59 * 58 * 57  # 11,703,240
    buf = bytearray(n * 10)
    msg = bytearray(43)
    msg[0] = FIRST
    msg[1] = second_char
    msg[6:27] = LABEL_S
    msg[27:43] = CHAL_C
    off = 0
    for perm in permutations(after_two, 4):
        msg[2] = perm[0]
        msg[3] = perm[1]
        msg[4] = perm[2]
        msg[5] = perm[3]
        h = blake3(msg).digest()
        buf[off:off + 4] = h[:4]
        buf[off + 4:off + 10] = msg[:6]
        off += 10
    arr = np.frombuffer(buf, dtype=DTYPE).copy()
    del buf
    arr.sort(order='h')
    path = f'{OUTDIR}/chunk_{second_idx:02d}.bin'
    arr.tofile(path)
    return second_idx, n


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    t0 = time.time()
    nproc = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    with mp.Pool(nproc) as pool:
        done = 0
        for idx, n in pool.imap_unordered(worker, range(61)):
            done += 1
            elapsed = time.time() - t0
            print(f'  [{done:2d}/61] chunk {idx:02d} done, elapsed {elapsed:.1f}s', flush=True)
    dt = time.time() - t0
    total = 61 * 60 * 59 * 58 * 57
    print(f'\nDone {total:,} hashes in {dt:.1f}s ({total/dt:,.0f} h/s)')
    print(f'Stored at {OUTDIR}/chunk_[00-60].bin')


if __name__ == '__main__':
    main()
