"""
Jeff's LFSR solver using fast bitwise LFSR simulation.
Correlation attack on Geffe generator.
"""
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import ctypes
import struct
import time

output = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

N = 256

def lfsr_stream_int(init, size, feedback_mask, length):
    """Fast LFSR using integer bit operations.
    init: integer with MSB = s[0]
    feedback_mask: which bits to XOR for feedback (bit positions from MSB)
    Returns list of output bits.
    """
    state = init
    mask = (1 << size) - 1
    result = []
    for _ in range(length):
        # Output is MSB
        result.append((state >> (size - 1)) & 1)
        # Compute feedback = popcount(state & feedback_mask) % 2
        fb = bin(state & feedback_mask).count('1') & 1
        # Shift left, insert feedback at LSB
        state = ((state << 1) | fb) & mask
    return result

# LFSR taps:
# LFSR0: key[:19], taps [19,18,17,14] -> _t = [0,1,2,5]
# feedback uses s[0], s[1], s[2], s[5] (indices into list)
# In integer representation (MSB = s[0]):
# s[0] = bit 18, s[1] = bit 17, s[2] = bit 16, s[5] = bit 13
# feedback_mask0 = (1<<18)|(1<<17)|(1<<16)|(1<<13)
fb0 = (1<<18)|(1<<17)|(1<<16)|(1<<13)

# LFSR1: key[19:46] (27 bits), taps [27,26,25,22] -> _t = [0,1,2,5]
# s[0]=bit26, s[1]=bit25, s[2]=bit24, s[5]=bit21
fb1 = (1<<26)|(1<<25)|(1<<24)|(1<<21)

# LFSR2: key[46:] (23 bits), taps [23,22,20,18] -> _t = [0,1,3,5]
# s[0]=bit22, s[1]=bit21, s[3]=bit19, s[5]=bit17
fb2 = (1<<22)|(1<<21)|(1<<19)|(1<<17)

# Convert output to integer for fast comparison
out_int = 0
for b in output:
    out_int = (out_int << 1) | b

# Pack output bits for fast correlation counting
# Use popcount on XOR of packed bits
def pack_bits(bits):
    """Pack bits into integers for fast popcount"""
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val

out_packed = pack_bits(output)

def count_correlation(stream_packed):
    """Count matching bits between stream and output using XOR + popcount"""
    diff = stream_packed ^ out_packed
    return N - bin(diff).count('1')

# Step 1: Brute force LFSR2 (23 bits)
print('Brute forcing LFSR2 (23 bits)...')
t0 = time.time()
candidates2 = []
best_s2 = 0
for k in range(1, 1 << 23):
    stream = lfsr_stream_int(k, 23, fb2, N)
    sp = pack_bits(stream)
    score = count_correlation(sp)
    if score > best_s2:
        best_s2 = score
    if score >= 176:
        candidates2.append(k)
        print(f'  LFSR2 candidate: {k}, score={score}')
print(f'LFSR2 done in {time.time()-t0:.1f}s, best={best_s2}, candidates={len(candidates2)}')

# Step 2: Brute force LFSR1 (27 bits)
print('Brute forcing LFSR1 (27 bits)...')
t0 = time.time()
candidates1 = []
best_s1 = 0
for k in range(1, 1 << 27):
    if k % (1 << 24) == 0:
        print(f'  Progress: {k >> 24}/8, elapsed {time.time()-t0:.1f}s')
    stream = lfsr_stream_int(k, 27, fb1, N)
    sp = pack_bits(stream)
    score = count_correlation(sp)
    if score > best_s1:
        best_s1 = score
    if score >= 176:
        candidates1.append(k)
        print(f'  LFSR1 candidate: {k}, score={score}')
print(f'LFSR1 done in {time.time()-t0:.1f}s, best={best_s1}, candidates={len(candidates1)}')

# Step 3: For each (key1, key2) pair, determine key0
print(f'Trying {len(candidates1)} x {len(candidates2)} combinations...')
for key1 in candidates1:
    stream1 = lfsr_stream_int(key1, 27, fb1, N)
    for key2 in candidates2:
        stream2 = lfsr_stream_int(key2, 23, fb2, N)
        # Determine required b0 bits
        required_b0 = []
        possible = True
        for i in range(N):
            s1m = stream1[i] == output[i]
            s2m = stream2[i] == output[i]
            if s1m and s2m:
                required_b0.append(-1)  # don't care
            elif s1m:
                required_b0.append(1)
            elif s2m:
                required_b0.append(0)
            else:
                possible = False
                break
        if not possible:
            continue

        # Brute force LFSR0 (19 bits)
        for key0 in range(1, 1 << 19):
            stream0 = lfsr_stream_int(key0, 19, fb0, N)
            match = True
            for i in range(N):
                if required_b0[i] != -1 and stream0[i] != required_b0[i]:
                    match = False
                    break
            if match:
                # Reconstruct the original key integer
                # key = [key0_bits(19)] + [key1_bits(27)] + [key2_bits(23)]
                # total 69 bits
                key_bits = []
                for bit in range(18, -1, -1):
                    key_bits.append((key0 >> bit) & 1)
                for bit in range(26, -1, -1):
                    key_bits.append((key1 >> bit) & 1)
                for bit in range(22, -1, -1):
                    key_bits.append((key2 >> bit) & 1)

                key = int(''.join(str(b) for b in key_bits), 2)
                print(f'Found! key0={key0}, key1={key1}, key2={key2}, full_key={key}')

                sha1 = hashlib.sha1()
                sha1.update(str(key).encode('ascii'))
                aes_key = sha1.digest()[:16]
                iv = bytes.fromhex('310c55961f7e45891022668eea77f805')
                ct = bytes.fromhex('2aa92761b36a4aad9a578d6cd7a62c52ba0709cb560c0ecff33a09e4af43bff0a1c865023bf28b387df91d6319f0e103d39dda88a88c14cfcec94c8ad02a6fb3152a4466c1a184f69184349e576d8950cac0a5b58bf30e67e5269883596a33a6')
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                try:
                    pt = unpad(cipher.decrypt(ct), 16)
                    print(f'Flag: {pt}')
                except:
                    print('Decryption failed, trying next...')
                    continue
                exit()

print('No solution found')
