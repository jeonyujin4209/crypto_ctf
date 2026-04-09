import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import numpy as np

output = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

N = 256
out_arr = np.array(output, dtype=np.int8)

def lfsr_stream_fast(key_int, size, taps, length):
    """Fast LFSR using integer bitops"""
    d = size
    t_indices = [d - t for t in taps]
    state = [(key_int >> (size - 1 - i)) & 1 for i in range(size)]
    result = []
    for _ in range(length):
        result.append(state[0])
        c = 0
        for p in t_indices:
            c ^= state[p]
        state = state[1:] + [c]
    return result

# Pre-compute all LFSR2 streams (23 bits = 8M)
print('Brute forcing LFSR2 (23 bits)...')
candidates2 = []
for k in range(1, 2**23):
    s = lfsr_stream_fast(k, 23, [23, 22, 20, 18], N)
    score = sum(1 for i in range(N) if s[i] == output[i])
    if score >= 176:
        candidates2.append(k)
        print(f'  LFSR2 candidate: {k}, score={score}')

print(f'LFSR2 candidates: {len(candidates2)}')

# Brute force LFSR1 (27 bits = 128M) - this is the bottleneck
print('Brute forcing LFSR1 (27 bits)...')
candidates1 = []
for k in range(1, 2**27):
    if k % (2**24) == 0:
        print(f'  Progress: {k}/{2**27}')
    s = lfsr_stream_fast(k, 27, [27, 26, 25, 22], N)
    score = sum(1 for i in range(N) if s[i] == output[i])
    if score >= 176:
        candidates1.append(k)
        print(f'  LFSR1 candidate: {k}, score={score}')

print(f'LFSR1 candidates: {len(candidates1)}')

# Try combinations
print(f'Trying {len(candidates1)} x {len(candidates2)} combinations with LFSR0 brute force...')
for key1 in candidates1:
    stream1 = lfsr_stream_fast(key1, 27, [27, 26, 25, 22], N)
    for key2 in candidates2:
        stream2 = lfsr_stream_fast(key2, 23, [23, 22, 20, 18], N)
        # For each position, determine what LFSR0 bit must be
        # output[i] = stream1[i] if b0[i] else stream2[i]
        # If stream1[i] == stream2[i] == output[i]: b0 can be 0 or 1
        # If stream1[i] == output[i] != stream2[i]: b0 must be 1
        # If stream2[i] == output[i] != stream1[i]: b0 must be 0
        # If stream1[i] != output[i] and stream2[i] != output[i]: impossible
        
        required_b0 = []
        possible = True
        for i in range(N):
            s1_match = stream1[i] == output[i]
            s2_match = stream2[i] == output[i]
            if s1_match and s2_match:
                required_b0.append(-1)  # don't care
            elif s1_match:
                required_b0.append(1)
            elif s2_match:
                required_b0.append(0)
            else:
                possible = False
                break
        
        if not possible:
            continue
        
        # Now check if required_b0 is consistent with a 19-bit LFSR
        # The constrained positions must match. Try all 2^19 LFSR0 keys.
        for key0 in range(1, 2**19):
            stream0 = lfsr_stream_fast(key0, 19, [19, 18, 17, 14], N)
            match = True
            for i in range(N):
                if required_b0[i] != -1 and stream0[i] != required_b0[i]:
                    match = False
                    break
            if match:
                key = (key0 << 50) | (key1 << 23) | key2
                print(f'Found! key0={key0}, key1={key1}, key2={key2}, full_key={key}')
                
                sha1 = hashlib.sha1()
                sha1.update(str(key).encode('ascii'))
                aes_key = sha1.digest()[:16]
                iv = bytes.fromhex('310c55961f7e45891022668eea77f805')
                ct = bytes.fromhex('2aa92761b36a4aad9a578d6cd7a62c52ba0709cb560c0ecff33a09e4af43bff0a1c865023bf28b387df91d6319f0e103d39dda88a88c14cfcec94c8ad02a6fb3152a4466c1a184f69184349e576d8950cac0a5b58bf30e67e5269883596a33a6')
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), 16)
                print(f'Flag: {pt}')
                exit()

print('No solution found')
