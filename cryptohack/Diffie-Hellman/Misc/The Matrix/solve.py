import numpy as np

N = 50
E = 31337

# Read ciphertext matrix (GF(2))
with open('flag.enc') as f:
    lines = f.read().strip().split('\n')
C = np.array([[int(c) for c in line] for line in lines], dtype=np.int64)

def mat_mul_gf2(A, B):
    return np.mod(A @ B, 2)

def mat_pow_gf2(M, exp):
    result = np.eye(N, dtype=np.int64)
    base = M.copy()
    while exp > 0:
        if exp & 1:
            result = mat_mul_gf2(result, base)
        base = mat_mul_gf2(base, base)
        exp >>= 1
    return result

# Compute |GL(50, GF(2))|
gl_order = 1
for i in range(50):
    gl_order *= (2**50 - 2**i)

# E is coprime to gl_order, so mat = C^(E^{-1} mod gl_order)
d = pow(E, -1, gl_order)
mat = mat_pow_gf2(C, d)

# Extract flag: msg[j] = rows[j % N][j // N]
msg_bits = []
rows = mat.tolist()
for j in range(N * N):
    msg_bits.append(rows[j % N][j // N])

bitstr = ''.join(str(b) for b in msg_bits)
flag_bytes = int(bitstr[:8*50], 2).to_bytes(50, 'big')
idx = flag_bytes.find(b'crypto{')
end = flag_bytes.find(b'}', idx)
print(flag_bytes[idx:end+1].decode())
# crypto{there_is_no_spoon_66eff188}
