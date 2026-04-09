import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

output = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

N = 256

# Use bitmask-based LFSR simulation for speed
def lfsr_stream_bits(init_state, size, taps_mask, length):
    """Generate LFSR stream using bitmasks"""
    state = init_state
    mask = (1 << size) - 1
    result = []
    for _ in range(length):
        b = (state >> (size - 1)) & 1  # output MSB (position 0 = MSB)
        result.append(b)
        # feedback
        fb = bin(state & taps_mask).count('1') % 2
        state = ((state << 1) | fb) & mask
    return result

# Taps for each LFSR:
# LFSR0: size=19, taps=[19,18,17,14] -> in _t: [19-19, 19-18, 19-17, 19-14] = [0,1,2,5]
# The feedback is: c = s[0]^s[1]^s[2]^s[5]
# In bitmask representation with MSB=s[0]: bits 18,17,16,13 (from MSB)
# taps_mask0 = (1<<18)|(1<<17)|(1<<16)|(1<<13)

# Actually let me just use a proper LFSR implementation
def lfsr_stream(key_int, size, taps, length):
    """taps as in original: feedback positions in _t = [d-t for t in taps]"""
    s = [(key_int >> (size - 1 - i)) & 1 for i in range(size)]
    d = size
    _t = [d - t for t in taps]
    result = []
    for _ in range(length):
        b = s[0]
        result.append(b)
        c = 0
        for p in _t:
            c ^= s[p]
        s = s[1:] + [c]
    return result

# Brute force LFSR2 first (23 bits = 2^23 ~8M, faster)
print('Brute forcing LFSR2 (23 bits)...')
best_score2 = 0
best_key2 = 0
candidates2 = []

for k in range(1, 2**23):
    stream2 = lfsr_stream(k, 23, [23, 22, 20, 18], N)
    score = sum(1 for i in range(N) if stream2[i] == output[i])
    if score > best_score2:
        best_score2 = score
        best_key2 = k
    if score >= 175:
        candidates2.append((k, score))
        print(f'  LFSR2 candidate: {k}, score={score}')

print(f'Best LFSR2: key={best_key2}, score={best_score2}')
print(f'Candidates: {len(candidates2)}')

# Then brute force LFSR1 (27 bits)
print('Brute forcing LFSR1 (27 bits)...')
best_score1 = 0
best_key1 = 0
candidates1 = []

for k in range(1, 2**27):
    stream1 = lfsr_stream(k, 27, [27, 26, 25, 22], N)
    score = sum(1 for i in range(N) if stream1[i] == output[i])
    if score > best_score1:
        best_score1 = score
        best_key1 = k
    if score >= 175:
        candidates1.append((k, score))
        print(f'  LFSR1 candidate: {k}, score={score}')

print(f'Best LFSR1: key={best_key1}, score={best_score1}')
print(f'Candidates: {len(candidates1)}')

# Now try all combinations of candidates
print(f'Trying {len(candidates1)} x {len(candidates2)} combinations...')
for key1, s1 in candidates1:
    stream1 = lfsr_stream(key1, 27, [27, 26, 25, 22], N)
    for key2, s2 in candidates2:
        stream2 = lfsr_stream(key2, 23, [23, 22, 20, 18], N)
        # Now brute force LFSR0 (19 bits)
        for key0 in range(1, 2**19):
            stream0 = lfsr_stream(key0, 19, [19, 18, 17, 14], N)
            # Check: output[i] = stream1[i] if stream0[i] else stream2[i]
            match = True
            for i in range(N):
                expected = stream1[i] if stream0[i] else stream2[i]
                if expected != output[i]:
                    match = False
                    break
            if match:
                # Reconstruct full key
                key = (key0 << 50) | (key1 << 23) | key2
                print(f'Found key! key0={key0}, key1={key1}, key2={key2}')
                print(f'Full key: {key}')
                
                # Decrypt
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
