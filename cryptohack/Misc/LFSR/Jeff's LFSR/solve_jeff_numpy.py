"""
Jeff's LFSR solver - vectorized correlation attack using numpy.
"""
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

output = np.array([1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1], dtype=np.int8)

N = 256

def lfsr_stream(init, size, feedback_taps, length):
    """Generate LFSR stream.
    feedback_taps: list of _t indices (positions to XOR for feedback)
    """
    state = [(init >> (size - 1 - i)) & 1 for i in range(size)]
    result = []
    for _ in range(length):
        result.append(state[0])
        c = 0
        for t in feedback_taps:
            c ^= state[t]
        state = state[1:] + [c]
    return result

# LFSR configs (using _t = [d-t for t in taps])
# LFSR0: d=19, taps=[19,18,17,14], _t=[0,1,2,5]
# LFSR1: d=27, taps=[27,26,25,22], _t=[0,1,2,5]
# LFSR2: d=23, taps=[23,22,20,18], _t=[0,1,3,5]

# Pre-generate ALL LFSR2 streams (2^23 = 8M, each 256 bits = 32 bytes)
# Store as a big numpy array for fast correlation
print('Pre-generating LFSR2 streams (2^23 = 8M)...')
t0 = time.time()

# Generate streams in batches
LFSR2_SIZE = 23
LFSR2_TAPS = [0, 1, 3, 5]
num2 = 1 << LFSR2_SIZE

streams2 = np.zeros((num2, N), dtype=np.int8)
for k in range(1, num2):
    s = lfsr_stream(k, LFSR2_SIZE, LFSR2_TAPS, N)
    streams2[k] = s

# Compute correlations with output
scores2 = np.sum(streams2 == output, axis=1)
best_idx2 = np.argsort(scores2)[::-1][:20]
print(f'LFSR2 done in {time.time()-t0:.1f}s')
print(f'Top LFSR2 scores: {[(int(i), int(scores2[i])) for i in best_idx2[:5]]}')

candidates2 = [int(i) for i in best_idx2 if scores2[i] >= 175]
print(f'LFSR2 candidates (score>=175): {len(candidates2)}')

# Now LFSR1 (2^27 = 128M) - do in chunks
print('Brute forcing LFSR1 (2^27 = 128M)...')
t0 = time.time()
LFSR1_SIZE = 27
LFSR1_TAPS = [0, 1, 2, 5]
num1 = 1 << LFSR1_SIZE

candidates1 = []
CHUNK = 1 << 20  # 1M at a time

for chunk_start in range(0, num1, CHUNK):
    chunk_end = min(chunk_start + CHUNK, num1)
    chunk_streams = np.zeros((chunk_end - chunk_start, N), dtype=np.int8)
    for k in range(chunk_start, chunk_end):
        if k == 0:
            continue
        s = lfsr_stream(k, LFSR1_SIZE, LFSR1_TAPS, N)
        chunk_streams[k - chunk_start] = s

    chunk_scores = np.sum(chunk_streams == output, axis=1)
    for idx in range(len(chunk_scores)):
        if chunk_scores[idx] >= 175:
            k = chunk_start + idx
            candidates1.append(k)
            print(f'  LFSR1 candidate: {k}, score={int(chunk_scores[idx])}')

    if (chunk_start // CHUNK) % 16 == 0:
        elapsed = time.time() - t0
        print(f'  Progress: {chunk_start}/{num1} ({100*chunk_start/num1:.1f}%), {elapsed:.1f}s')

print(f'LFSR1 done in {time.time()-t0:.1f}s, candidates: {len(candidates1)}')

# Step 3: For each pair, determine LFSR0
LFSR0_SIZE = 19
LFSR0_TAPS = [0, 1, 2, 5]

print(f'Checking {len(candidates1)} x {len(candidates2)} combinations...')
for key1 in candidates1:
    stream1 = lfsr_stream(key1, LFSR1_SIZE, LFSR1_TAPS, N)
    for key2 in candidates2:
        stream2 = lfsr_stream(key2, LFSR2_SIZE, LFSR2_TAPS, N)

        required_b0 = []
        possible = True
        for i in range(N):
            s1m = stream1[i] == output[i]
            s2m = stream2[i] == output[i]
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

        for key0 in range(1, 1 << LFSR0_SIZE):
            stream0 = lfsr_stream(key0, LFSR0_SIZE, LFSR0_TAPS, N)
            match = all(required_b0[i] == -1 or stream0[i] == required_b0[i] for i in range(N))
            if match:
                key_bits = []
                for bit in range(18, -1, -1):
                    key_bits.append((key0 >> bit) & 1)
                for bit in range(26, -1, -1):
                    key_bits.append((key1 >> bit) & 1)
                for bit in range(22, -1, -1):
                    key_bits.append((key2 >> bit) & 1)
                key = int(''.join(str(b) for b in key_bits), 2)
                print(f'Found! key0={key0}, key1={key1}, key2={key2}, key={key}')

                sha1 = hashlib.sha1()
                sha1.update(str(key).encode('ascii'))
                aes_key = sha1.digest()[:16]
                iv = bytes.fromhex('310c55961f7e45891022668eea77f805')
                ct = bytes.fromhex('2aa92761b36a4aad9a578d6cd7a62c52ba0709cb560c0ecff33a09e4af43bff0a1c865023bf28b387df91d6319f0e103d39dda88a88c14cfcec94c8ad02a6fb3152a4466c1a184f69184349e576d8950cac0a5b58bf30e67e5269883596a33a6')
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                try:
                    pt = unpad(cipher.decrypt(ct), 16)
                    print(f'Flag: {pt}')
                    exit()
                except:
                    continue

print('No solution found')
