#!/usr/bin/env python3
"""
SpongeBob SquarePants / Battle for Bikini Bottom - Rehydrated (HTB Cyber Apocalypse)
Custom sponge hash collision via SBOX backdoor + birthday attack.

Backdoor: SBOX preserves bits 2,4,5=0 (invariant subspace).
Permute also preserves bit index → invariant propagates through all rounds.
INIT capacity already satisfies the invariant.

Effective capacity: 10 * 5 = 50 bits → birthday ~2^25.
Uses numpy for batch hash computation (~100x speedup over pure Python).
"""

import numpy as np
import time
from pwn import remote
from spongebob import SBOX, PBOXES, INIT, permute, H, BLOCKSIZE

MASK = 0x04 | 0x10 | 0x20  # bits 2, 4, 5
FREE_BITS = [0, 1, 3, 6, 7]  # 5 free bits per byte
FORCED = [INIT[i] & MASK for i in range(8)]

# Precompute
SBOX_ARR = np.array(SBOX, dtype=np.uint8)
INV_PBOXES = [[0]*18 for _ in range(8)]
for b in range(8):
    for i in range(18):
        INV_PBOXES[b][PBOXES[b][i]] = i
INV_PBOXES = [np.array(p, dtype=np.intp) for p in INV_PBOXES]
INIT_ARR = np.array(INIT, dtype=np.uint8)


def batch_hash(blocks):
    """Compute state after one block for N inputs using numpy."""
    N = len(blocks)
    states = np.tile(INIT_ARR, (N, 1)).copy()
    states[:, :8] ^= blocks

    for _ in range(8):
        # Permute: for each bit plane, gather from source positions
        new_states = np.zeros_like(states)
        for b in range(8):
            m = np.uint8(1 << b)
            gathered = states[:, INV_PBOXES[b]]  # (N, 18)
            new_states |= (gathered & m)
        states = new_states
        # SBOX
        states = SBOX_ARR[states]

    return states


def gen_blocks(N):
    """Generate N random blocks preserving the invariant."""
    blocks = np.zeros((N, 8), dtype=np.uint8)
    for i in range(8):
        blocks[:, i] = np.uint8(FORCED[i])
        for b in FREE_BITS:
            bits = np.random.randint(0, 2, N, dtype=np.uint8)
            blocks[:, i] |= (bits << b).astype(np.uint8)
    return blocks


def cap_to_key(state_row):
    """Extract 50-bit capacity key as bytes (for dict hashing)."""
    return bytes(state_row[8:18])


def birthday_attack():
    """Batch birthday attack on 50-bit effective capacity."""
    BATCH = 200000
    seen = {}  # cap_key -> block (as bytes)
    total = 0
    t0 = time.time()

    while True:
        blocks = gen_blocks(BATCH)
        states = batch_hash(blocks)

        for idx in range(BATCH):
            block = bytes(blocks[idx])
            cap = bytes(states[idx, 8:18])

            if cap in seen:
                old_block = seen[cap]
                if old_block != block:
                    elapsed = time.time() - t0
                    total += idx
                    print(f"Collision after {total} hashes ({elapsed:.1f}s)")
                    # Compute full states
                    state_a = compute_state_single(old_block)
                    state_b = compute_state_single(block)
                    return (old_block, state_a), (block, state_b)

            seen[cap] = block

        total += BATCH
        elapsed = time.time() - t0
        rate = total / elapsed
        print(f"  {total} hashes, {rate:.0f}/s, {len(seen)} unique caps")


def compute_state_single(block_bytes):
    """Compute state for a single block (pure Python)."""
    state = list(INIT)
    for i in range(8):
        state[i] ^= block_bytes[i]
    for _ in range(8):
        state = permute(state)
        state = [SBOX[b] for b in state]
    return state


def build_collision(pair_a, pair_b):
    """Build 2-block messages from capacity collision."""
    block_a, state_a = pair_a
    block_b, state_b = pair_b

    assert state_a[8:] == state_b[8:], "Capacity mismatch!"

    c = bytes(8)  # second block for msg1
    c_prime = bytes([c[i] ^ state_a[i] ^ state_b[i] for i in range(8)])

    msg1 = block_a + c
    msg2 = block_b + c_prime
    return msg1, msg2


def main():
    print("SBOX backdoor birthday attack (50-bit capacity)...")
    pair_a, pair_b = birthday_attack()

    block_a, state_a = pair_a
    block_b, state_b = pair_b
    print(f"  block_a = {block_a.hex()}")
    print(f"  block_b = {block_b.hex()}")

    msg1, msg2 = build_collision(pair_a, pair_b)
    print(f"  msg1 = {msg1.hex()}")
    print(f"  msg2 = {msg2.hex()}")

    # Verify
    h1 = H(list(msg1))
    h2 = H(list(msg2))
    print(f"  H(msg1) = {h1.hex()}")
    print(f"  H(msg2) = {h2.hex()}")
    assert msg1 != msg2, "Messages are the same!"
    assert h1 == h2, "Hash mismatch!"
    print("Collision verified!")

    # Submit
    HOST = "archive.cryptohack.org"
    PORT = 37916
    r = remote(HOST, PORT)
    r.recvuntil(b"sea?")
    r.sendlineafter(b"> ", msg1.hex().encode())
    r.sendlineafter(b"> ", msg2.hex().encode())
    print(r.recvline().strip().decode())
    r.close()


if __name__ == "__main__":
    main()
