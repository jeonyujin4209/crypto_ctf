"""
Jeff's LFSR solver - optimized with known LFSR2 candidates.
"""
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import sys

output_list = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

N = 256

def build_lfsr_matrix(size, taps_t, length):
    M = np.zeros((length, size), dtype=np.uint8)
    state_vecs = np.eye(size, dtype=np.uint8)
    for t in range(length):
        M[t] = state_vecs[0]
        fb = np.zeros(size, dtype=np.uint8)
        for p in taps_t:
            fb = fb ^ state_vecs[p]
        state_vecs = np.vstack([state_vecs[1:], fb.reshape(1, -1)])
    return M

print('Building LFSR matrices...', flush=True)
M0 = build_lfsr_matrix(19, [0,1,2,5], N)
M1 = build_lfsr_matrix(27, [0,1,2,5], N)
M2 = build_lfsr_matrix(23, [0,1,3,5], N)

# Pack output
out_packed = 0
for b in output_list:
    out_packed = (out_packed << 1) | b

def pack_columns(M, size):
    cols = []
    for j in range(size):
        val = 0
        for i in range(N):
            val = (val << 1) | int(M[i][j])
        cols.append(val)
    return cols

cols0 = pack_columns(M0, 19)
cols1 = pack_columns(M1, 27)
cols2 = pack_columns(M2, 23)

def get_stream_packed(k, cols, size):
    stream = 0
    j = size - 1
    kk = k
    while kk:
        if kk & 1:
            stream ^= cols[j]
        kk >>= 1
        j -= 1
    return stream

def unpack_bits(packed, length):
    return [(packed >> (length - 1 - i)) & 1 for i in range(length)]

# Phase 1: LFSR2 (23 bits)
print('Phase 1: LFSR2...', flush=True)
t0 = time.time()
candidates2 = []
for k in range(1, 1 << 23):
    sp = get_stream_packed(k, cols2, 23)
    diff = sp ^ out_packed
    score = N - bin(diff).count('1')
    if score >= 175:
        candidates2.append((k, score))
        print(f'  LFSR2: k={k}, score={score}', flush=True)
print(f'LFSR2 done in {time.time()-t0:.0f}s, {len(candidates2)} candidates', flush=True)

# Phase 2: LFSR1 (27 bits)
print('Phase 2: LFSR1...', flush=True)
t0 = time.time()
candidates1 = []
for k in range(1, 1 << 27):
    sp = get_stream_packed(k, cols1, 27)
    diff = sp ^ out_packed
    score = N - bin(diff).count('1')
    if score >= 175:
        candidates1.append((k, score))
        print(f'  LFSR1: k={k}, score={score}', flush=True)
    if k % (1 << 24) == 0:
        print(f'  Progress: {k >> 24}/8, {time.time()-t0:.0f}s', flush=True)
print(f'LFSR1 done in {time.time()-t0:.0f}s, {len(candidates1)} candidates', flush=True)

# Phase 3: Match pairs
print(f'Phase 3: {len(candidates1)} x {len(candidates2)} combinations...', flush=True)
for key1, _ in candidates1:
    s1_bits = unpack_bits(get_stream_packed(key1, cols1, 27), N)
    for key2, _ in candidates2:
        s2_bits = unpack_bits(get_stream_packed(key2, cols2, 23), N)

        required_b0 = []
        possible = True
        for i in range(N):
            s1m = s1_bits[i] == output_list[i]
            s2m = s2_bits[i] == output_list[i]
            if s1m and s2m:
                required_b0.append(-1)
            elif s1m:
                required_b0.append(1)
            elif s2m:
                required_b0.append(0)
            else:
                possible = False
                break
        if not possible:
            continue

        # Solve GF(2) linear system for LFSR0
        constrained = [(i, required_b0[i]) for i in range(N) if required_b0[i] != -1]
        A = np.array([M0[i] for i, _ in constrained], dtype=np.uint8)
        b = np.array([v for _, v in constrained], dtype=np.uint8)

        m_rows, n_cols = A.shape
        aug = np.hstack([A, b.reshape(-1, 1)]).copy()

        pivot_cols = []
        row = 0
        for col in range(n_cols):
            found = -1
            for r in range(row, m_rows):
                if aug[r, col]:
                    found = r
                    break
            if found == -1:
                continue
            aug[[row, found]] = aug[[found, row]].copy()
            for r in range(m_rows):
                if r != row and aug[r, col]:
                    aug[r] ^= aug[row]
            pivot_cols.append(col)
            row += 1

        consistent = all(aug[r, -1] == 0 for r in range(row, m_rows))
        if not consistent:
            continue

        state0 = np.zeros(n_cols, dtype=np.uint8)
        for i, col in enumerate(pivot_cols):
            state0[col] = aug[i, -1]

        free_cols = [c for c in range(n_cols) if c not in pivot_cols]

        for fv in range(1 << len(free_cols)):
            s0 = state0.copy()
            for idx, fc in enumerate(free_cols):
                s0[fc] = (fv >> idx) & 1

            k0 = int(''.join(str(x) for x in s0), 2)
            if k0 == 0:
                continue

            key_bits = list(s0)
            for bit in range(26, -1, -1):
                key_bits.append((key1 >> bit) & 1)
            for bit in range(22, -1, -1):
                key_bits.append((key2 >> bit) & 1)
            key = int(''.join(str(b) for b in key_bits), 2)

            sha1 = hashlib.sha1()
            sha1.update(str(key).encode('ascii'))
            aes_key = sha1.digest()[:16]
            iv = bytes.fromhex('310c55961f7e45891022668eea77f805')
            ct = bytes.fromhex('2aa92761b36a4aad9a578d6cd7a62c52ba0709cb560c0ecff33a09e4af43bff0a1c865023bf28b387df91d6319f0e103d39dda88a88c14cfcec94c8ad02a6fb3152a4466c1a184f69184349e576d8950cac0a5b58bf30e67e5269883596a33a6')
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            try:
                pt = unpad(cipher.decrypt(ct), 16)
                print(f'Found! key={key}', flush=True)
                print(f'Flag: {pt}', flush=True)
                sys.exit(0)
            except:
                pass

print('No solution found')
