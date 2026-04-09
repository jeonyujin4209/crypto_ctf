"""
Jeff's LFSR solver - fast approach using Walsh-Hadamard correlation.
The Geffe generator: out = b1 if b0 else b2.
Correlation with LFSR1: 0.75 (when b0=1, out=b1; when b0=0, out=b2, matches b1 50%)
Correlation with LFSR2: 0.75 (symmetric)

Key insight: Use fast correlation attack.
For an LFSR with known taps but unknown initial state, the output is a LINEAR
function of the initial state bits over GF(2). So correlation with the observed
output can be computed as a linear algebra problem.

For LFSR with size s and known taps, the output bit at time t is a linear function
of the initial state: out_t = sum(M[t][i] * state[i]) for i in 0..s-1 (over GF(2)).

The correlation attack: for each LFSR, compute the expected output matrix M,
then find the initial state that maximizes correlation with the observed output.
This is equivalent to: find state s that minimizes Hamming distance between M*s and output.
This is a nearest-codeword problem, which for specific LFSR sizes can be solved.

But actually, for the Geffe generator with sizes 19, 23, 27, the direct brute force
is feasible if we optimize the inner loop. Let me use numpy array ops.
"""
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

output_list = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

N = 256

def build_lfsr_matrix(size, taps_t, length):
    """Build the output matrix M where output[t] = sum M[t][i] * state[i] over GF(2).
    taps_t: the _t indices used for feedback
    Returns numpy array of shape (length, size) over GF(2)
    """
    # Each row of M gives the linear combination of initial state bits that produces output bit t
    M = np.zeros((length, size), dtype=np.uint8)
    # Initialize: at time 0, output = state[0], so M[0] = e_0
    # We simulate the LFSR symbolically
    # state[i] is represented as a vector of GF(2) coefficients over initial state bits
    state_vecs = np.eye(size, dtype=np.uint8)  # state_vecs[i] = coefficients for state[i]

    for t in range(length):
        M[t] = state_vecs[0]
        # Compute feedback
        fb = np.zeros(size, dtype=np.uint8)
        for p in taps_t:
            fb = fb ^ state_vecs[p]
        # Shift
        state_vecs = np.vstack([state_vecs[1:], fb.reshape(1, -1)])

    return M

# Build output matrices for each LFSR
print('Building LFSR matrices...')
M0 = build_lfsr_matrix(19, [0,1,2,5], N)  # LFSR0: 19 bits, _t=[0,1,2,5]
M1 = build_lfsr_matrix(27, [0,1,2,5], N)  # LFSR1: 27 bits, _t=[0,1,2,5]
M2 = build_lfsr_matrix(23, [0,1,3,5], N)  # LFSR2: 23 bits, _t=[0,1,3,5]

output = np.array(output_list, dtype=np.uint8)

# For correlation attack: want to find state that maximizes matches
# matches = count of t where (M*state)[t] == output[t]
# = count of t where (M*state XOR output)[t] == 0
# = N - hamming_weight(M*state XOR output)
# Maximize matches = minimize hamming_weight(M*state XOR output)

# For LFSR2 (23 bits = 8M states):
# For each candidate state s (23-bit vector), compute M2*s (mod 2) and count matches
print('Brute forcing LFSR2 (23 bits)...')
t0 = time.time()

# Optimization: precompute M2 as packed columns for fast multiplication
# For each state bit pattern, the output is the XOR of selected columns of M2
# We can process this efficiently

best_score2 = 0
candidates2 = []

# Use bit-parallel approach: represent output as integers
out_packed = 0
for b in output_list:
    out_packed = (out_packed << 1) | b

# Pack each column of M2 into a Python int
cols2 = []
for j in range(23):
    val = 0
    for i in range(N):
        val = (val << 1) | int(M2[i][j])
    cols2.append(val)

for k in range(1, 1 << 23):
    # Compute M2 * state_k: XOR of columns where state bit is 1
    stream_packed = 0
    kk = k
    j = 22
    while kk:
        if kk & 1:
            stream_packed ^= cols2[j]
        kk >>= 1
        j -= 1

    # Count matches: bits where stream_packed == out_packed
    diff = stream_packed ^ out_packed
    matches = N - bin(diff).count('1')
    if matches > best_score2:
        best_score2 = matches
    if matches >= 175:
        candidates2.append(k)
        if matches >= 180:
            print(f'  LFSR2 candidate: {k}, score={matches}')

print(f'LFSR2 done in {time.time()-t0:.1f}s, best={best_score2}, {len(candidates2)} candidates')

# LFSR1 (27 bits = 128M states)
print('Brute forcing LFSR1 (27 bits)...')
t0 = time.time()

cols1 = []
for j in range(27):
    val = 0
    for i in range(N):
        val = (val << 1) | int(M1[i][j])
    cols1.append(val)

best_score1 = 0
candidates1 = []

for k in range(1, 1 << 27):
    stream_packed = 0
    kk = k
    j = 26
    while kk:
        if kk & 1:
            stream_packed ^= cols1[j]
        kk >>= 1
        j -= 1

    diff = stream_packed ^ out_packed
    matches = N - bin(diff).count('1')
    if matches > best_score1:
        best_score1 = matches
    if matches >= 175:
        candidates1.append(k)
        if matches >= 180:
            print(f'  LFSR1 candidate: {k}, score={matches}')

    if k % (1 << 24) == 0:
        print(f'  Progress: {k >> 24}/8, {time.time()-t0:.1f}s')

print(f'LFSR1 done in {time.time()-t0:.1f}s, best={best_score1}, {len(candidates1)} candidates')

# Step 3: For each pair, determine LFSR0
cols0 = []
for j in range(19):
    val = 0
    for i in range(N):
        val = (val << 1) | int(M0[i][j])
    cols0.append(val)

def get_stream_bits(k, cols, size):
    """Get packed stream from key and column representation"""
    stream_packed = 0
    kk = k
    j = size - 1
    while kk:
        if kk & 1:
            stream_packed ^= cols[j]
        kk >>= 1
        j -= 1
    return stream_packed

def unpack_bits(packed, length):
    bits = []
    for i in range(length):
        bits.append((packed >> (length - 1 - i)) & 1)
    return bits

print(f'Checking {len(candidates1)} x {len(candidates2)} combinations...')
for key1 in candidates1:
    s1_packed = get_stream_bits(key1, cols1, 27)
    s1_bits = unpack_bits(s1_packed, N)
    for key2 in candidates2:
        s2_packed = get_stream_bits(key2, cols2, 23)
        s2_bits = unpack_bits(s2_packed, N)

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

        # Need LFSR0 stream that matches required_b0 at constrained positions
        # required_b0[i] = stream0[i] at non-(-1) positions
        # stream0 = M0 * state0, so we need M0*state0 to match at specific positions
        # This is a system of linear equations over GF(2)!

        constrained = [(i, required_b0[i]) for i in range(N) if required_b0[i] != -1]
        # Build system: M0[i] * state = required_b0[i] for each constrained i
        A = np.array([M0[i] for i, _ in constrained], dtype=np.uint8)
        b = np.array([v for _, v in constrained], dtype=np.uint8)

        # Solve A*x = b over GF(2) using Gaussian elimination
        m_rows, n_cols = A.shape
        aug = np.hstack([A, b.reshape(-1, 1)])

        pivot_cols = []
        row = 0
        for col in range(n_cols):
            # Find pivot
            found = -1
            for r in range(row, m_rows):
                if aug[r, col]:
                    found = r
                    break
            if found == -1:
                continue
            aug[[row, found]] = aug[[found, row]]
            for r in range(m_rows):
                if r != row and aug[r, col]:
                    aug[r] ^= aug[row]
            pivot_cols.append(col)
            row += 1

        # Check consistency
        consistent = True
        for r in range(row, m_rows):
            if aug[r, -1]:
                consistent = False
                break

        if not consistent:
            continue

        # Extract solution
        state0 = np.zeros(n_cols, dtype=np.uint8)
        for i, col in enumerate(pivot_cols):
            state0[col] = aug[i, -1]

        # Convert to integer
        key0 = 0
        for bit in state0:
            key0 = (key0 << 1) | int(bit)

        if key0 == 0:
            # Try free variables
            free_cols = [c for c in range(n_cols) if c not in pivot_cols]
            # Try all combinations of free variables
            for fv in range(1 << len(free_cols)):
                s0 = state0.copy()
                for idx, fc in enumerate(free_cols):
                    s0[fc] = (fv >> idx) & 1
                k0 = 0
                for bit in s0:
                    k0 = (k0 << 1) | int(bit)
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
                    print(f'Found! key={key}')
                    print(f'Flag: {pt}')
                    exit()
                except:
                    pass
            continue

        # Try this solution
        key_bits = list(state0)
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
            print(f'Found! key={key}')
            print(f'Flag: {pt}')
            exit()
        except:
            # Try free variables
            free_cols = [c for c in range(n_cols) if c not in pivot_cols]
            for fv in range(1, 1 << len(free_cols)):
                s0 = state0.copy()
                for idx, fc in enumerate(free_cols):
                    s0[fc] ^= (fv >> idx) & 1
                key_bits = list(s0)
                for bit in range(26, -1, -1):
                    key_bits.append((key1 >> bit) & 1)
                for bit in range(22, -1, -1):
                    key_bits.append((key2 >> bit) & 1)
                key = int(''.join(str(b) for b in key_bits), 2)

                sha1 = hashlib.sha1()
                sha1.update(str(key).encode('ascii'))
                aes_key = sha1.digest()[:16]
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                try:
                    pt = unpad(cipher.decrypt(ct), 16)
                    print(f'Found! key={key}')
                    print(f'Flag: {pt}')
                    exit()
                except:
                    pass

print('No solution found')
