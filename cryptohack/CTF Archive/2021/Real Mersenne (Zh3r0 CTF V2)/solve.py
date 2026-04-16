"""
Real Mersenne (Zh3r0 CTF V2) — Mersenne Twister state recovery from float leaks.

Score formula leaks int(2^53 * x) = (genrand1>>5)<<26 | (genrand2>>6), giving
27+26=53 bits of info per round (11 bits hidden per MT-word pair).

Approach:
  Phase 1: Send y=0 for 700 rounds to harvest 1400 partial MT outputs.
  Phase 2: Z3 model with MT state + 3 twist applications → recover initial state.
  Phase 3: Clone random.Random(), predict future rounds, match exactly for score=1024.

Budget: 700*~7 + 1300*1024 ≈ 1,336,000 > 10^6 ✓
"""
from pwn import *
from z3 import *
import random as pyrandom
import time

HOST = 'archive.cryptohack.org'
PORT = 16189
N_LEARN = 700

N_MT, M_MT = 624, 397
MATRIX_A = 0x9908b0df
UPPER_MASK, LOWER_MASK = 0x80000000, 0x7fffffff

def temper(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ LShR(y, 18)
    return y

def mt_twist_z3(state):
    """In-place twist: phase-2 and last-element updates reference already-new values."""
    new = [None] * N_MT
    for i in range(N_MT - M_MT):
        y = (state[i] & UPPER_MASK) | (state[i+1] & LOWER_MASK)
        mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
        new[i] = state[i + M_MT] ^ LShR(y, 1) ^ mag
    for i in range(N_MT - M_MT, N_MT - 1):
        y = (state[i] & UPPER_MASK) | (state[i+1] & LOWER_MASK)
        mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
        new[i] = new[i + M_MT - N_MT] ^ LShR(y, 1) ^ mag
    i = N_MT - 1
    y = (state[i] & UPPER_MASK) | (new[0] & LOWER_MASK)
    mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
    new[i] = new[M_MT - 1] ^ LShR(y, 1) ^ mag
    return new

def recover_state(pairs_53bit):
    total_outs = 2 * len(pairs_53bit)
    n_twists = max(1, (total_outs + N_MT - 1) // N_MT)
    s = Solver()
    states_orig = [BitVec(f's0_{i}', 32) for i in range(N_MT)]
    all_outs = []
    cur = states_orig
    for _ in range(n_twists):
        cur = mt_twist_z3(cur)
        all_outs.extend(cur)
    n_added = 0
    for i, x_53 in enumerate(pairs_53bit):
        if x_53 is None:
            continue
        a = x_53 >> 26
        b = x_53 & ((1 << 26) - 1)
        s.add(LShR(temper(all_outs[2*i]),   5) == a)
        s.add(LShR(temper(all_outs[2*i+1]), 6) == b)
        n_added += 1
    log.info(f"Z3 solving ({n_twists} twists, {n_added} rounds of constraints)...")
    t = time.time()
    res = s.check()
    log.info(f"Z3 done in {time.time()-t:.1f}s: {res}")
    if res != sat:
        return None
    m = s.model()
    return [m[v].as_long() for v in states_orig]

def parse_round_score(line):
    rs = line.split('round score: ')[1].strip()
    if '/' in rs:
        num, den = map(int, rs.split('/'))
        return (2**53 * den) // num
    return None

def main():
    r = remote(HOST, PORT)

    pairs = []
    log.info(f"Phase 1: collecting {N_LEARN} rounds with y=0...")
    for i in range(N_LEARN):
        r.recvuntil(b'enter your guess:\n')
        r.sendline(b'0')
        line = r.recvline().decode().strip()
        pairs.append(parse_round_score(line))
        if (i + 1) % 100 == 0:
            log.info(f"  {i+1}/{N_LEARN}")

    state = recover_state(pairs)
    if state is None:
        log.error("Recovery failed!")
        r.close()
        return

    rnd = pyrandom.Random()
    rnd.setstate((3, tuple(state + [624]), None))
    for _ in range(N_LEARN):
        rnd.random()

    log.info(f"Phase 3: predicting rounds {N_LEARN}..2000")
    for i in range(N_LEARN, 2000):
        x_pred = rnd.random()
        r.recvuntil(b'enter your guess:\n')
        r.sendline(repr(x_pred).encode())
        line = r.recvline().decode().strip()
        if 'total score' in line:
            ts = float(line.split('total score: ')[1].split(',')[0])
            if ts > 10**6:
                flag = r.recvline().decode().strip()
                log.success(f"FLAG: {flag}")
                r.close()
                return
            if i % 200 == 0:
                log.info(f"  round {i}: total={ts:.0f}")
        else:
            log.warning(f"unexpected: {line}")
            break

    r.close()

if __name__ == '__main__':
    main()
