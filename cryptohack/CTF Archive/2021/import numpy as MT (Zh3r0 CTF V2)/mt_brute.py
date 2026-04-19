"""Brute-force numpy MT19937 32-bit seed from first 4 uint32 outputs.

numpy.random.seed(n):
  state[0] = n
  state[i] = 1812433253 * (state[i-1] ^ (state[i-1]>>30)) + i  (mod 2^32), i=1..623
  pos = 624 (first read triggers twist)

First read (bytes(16)): twist, then pos=0..3 tempered outputs.
twist state[0..3]_new depends on state[0..4] and state[397..400].
"""
import numpy as np
from numba import njit, prange
import struct
import time


def untemper(y):
    def inv_right(y, shift):
        res = 0
        for i in range(31, -1, -1):
            bit = (y >> i) & 1
            if i + shift < 32:
                bit ^= (res >> (i + shift)) & 1
            res |= bit << i
        return res
    def inv_left(y, shift, mask):
        res = 0
        for i in range(32):
            bit = (y >> i) & 1
            if i >= shift:
                bit ^= ((res >> (i - shift)) & 1) & ((mask >> i) & 1)
            res |= bit << i
        return res
    y = inv_right(y, 18)
    y = inv_left(y, 15, 0xEFC60000)
    y = inv_left(y, 7, 0x9D2C5680)
    y = inv_right(y, 11)
    return y & 0xFFFFFFFF


MATRIX_A = 0x9908B0DF
UPPER = 0x80000000
LOWER = 0x7FFFFFFF
MULT = 1812433253


@njit(cache=True, parallel=True)
def brute_seed(target0, target1, target2, target3, start, end):
    """Try seeds in [start, end). Return found seed or 0xFFFFFFFFFFFFFFFF."""
    found = np.uint64(0xFFFFFFFFFFFFFFFF)
    chunk = 1 << 16  # each parallel worker processes chunks
    n = (end - start + chunk - 1) // chunk
    result = np.full(n, 0xFFFFFFFFFFFFFFFF, dtype=np.uint64)
    for idx in prange(n):
        lo = start + idx * chunk
        hi = min(lo + chunk, end)
        for seed in range(lo, hi):
            # Compute state[0..400]
            s0 = np.uint32(seed)
            s1 = np.uint32(MULT * (s0 ^ (s0 >> 30)) + 1)
            # Iterate to state[400]
            s = s1
            states = np.empty(401, dtype=np.uint32)
            states[0] = s0
            states[1] = s1
            for i in range(2, 401):
                states[i] = np.uint32(MULT * (s ^ (s >> 30)) + np.uint32(i))
                s = states[i]
            # twist state[0]_new
            y = (states[0] & UPPER) | (states[1] & LOWER)
            m0 = MATRIX_A if (states[1] & 1) else 0
            new0 = states[397] ^ (y >> 1) ^ np.uint32(m0)
            if new0 == target0:
                y = (states[1] & UPPER) | (states[2] & LOWER)
                m1 = MATRIX_A if (states[2] & 1) else 0
                new1 = states[398] ^ (y >> 1) ^ np.uint32(m1)
                if new1 == target1:
                    y = (states[2] & UPPER) | (states[3] & LOWER)
                    m2 = MATRIX_A if (states[3] & 1) else 0
                    new2 = states[399] ^ (y >> 1) ^ np.uint32(m2)
                    if new2 == target2:
                        y = (states[3] & UPPER) | (states[4] & LOWER)
                        m3 = MATRIX_A if (states[4] & 1) else 0
                        new3 = states[400] ^ (y >> 1) ^ np.uint32(m3)
                        if new3 == target3:
                            result[idx] = seed
    for v in result:
        if v != 0xFFFFFFFFFFFFFFFF:
            return v
    return found


def find_seed(iv16):
    u = struct.unpack('<IIII', iv16)
    targets = [untemper(x) for x in u]
    print(f'  targets: {[hex(t) for t in targets]}')
    t0 = time.time()
    seed = brute_seed(
        np.uint32(targets[0]), np.uint32(targets[1]),
        np.uint32(targets[2]), np.uint32(targets[3]),
        0, 1 << 32
    )
    print(f'  brute time: {time.time()-t0:.1f}s, seed={hex(seed)}')
    if seed == 0xFFFFFFFFFFFFFFFF:
        return None
    return int(seed)


if __name__ == '__main__':
    # Self-test
    from numpy import random
    test_seed = 0xAABBCCDD
    random.seed(test_seed)
    iv = random.bytes(16)
    print(f'test seed={hex(test_seed)}, iv={iv.hex()}')
    found = find_seed(iv)
    print(f'found={hex(found) if found else None}')
    assert found == test_seed
    print('OK')
