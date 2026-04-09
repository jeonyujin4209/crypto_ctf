"""
Nativity: LWE implemented with numpy uint16 so all arithmetic is mod 2^16.
Key observation: decryption is sk.dot(c) & 1 (mod 2 only).
Since everything is mod 2^16, the LSB depends only on LSBs of inputs.

pk is (n+1) x m with top n rows being A (uniform) and the last row being
    s @ A + 2*e   (mod 2^16)
Reducing mod 2, the last row equals (s mod 2) @ (A mod 2) (mod 2).
So we can solve for s mod 2 over GF(2) using m = 512 >> n = 64 samples.
Then sk mod 2 = ([-s, 1] mod 2) = ([s, 1] mod 2).
"""
import numpy as np
from Crypto.Util.number import long_to_bytes

n = 64
m = 512

pk = np.loadtxt("public_key.txt", dtype=np.int64)
ct = np.loadtxt("ciphertexts.txt", dtype=np.int64)
print("pk.shape =", pk.shape)
print("ct.shape =", ct.shape)

A = pk[:n, :] & 1   # (n, m)
b = pk[n, :] & 1    # (m,)

# Solve s @ A = b (mod 2) over GF(2), s has length n.
# Equivalently A^T @ s = b (mod 2).
def gf2_solve(M, v):
    """Solve M @ x = v over GF(2). Returns one solution (or None)."""
    M = M.copy() & 1
    v = v.copy() & 1
    rows, cols = M.shape
    aug = np.hstack([M, v.reshape(-1, 1)]).astype(np.uint8)
    r = 0
    pivots = []
    for c in range(cols):
        # Find pivot row
        pivot = None
        for i in range(r, rows):
            if aug[i, c] == 1:
                pivot = i
                break
        if pivot is None:
            continue
        aug[[r, pivot]] = aug[[pivot, r]]
        for i in range(rows):
            if i != r and aug[i, c] == 1:
                aug[i] ^= aug[r]
        pivots.append((r, c))
        r += 1
        if r == rows:
            break
    # Check consistency
    for i in range(r, rows):
        if aug[i, cols] == 1:
            return None
    x = np.zeros(cols, dtype=np.uint8)
    for rr, cc in pivots:
        x[cc] = aug[rr, cols]
    return x

M = A.T  # (m, n)
s_mod2 = gf2_solve(M, b)
assert s_mod2 is not None
print(f"s mod 2 = {s_mod2}")

# Verify
check = (A.T @ s_mod2) & 1
assert np.array_equal(check & 1, b & 1), "s mod 2 verification failed"
print("s mod 2 verified.")

# sk = [-s, 1] mod 2^16, so sk mod 2 = [s, 1] mod 2 (since -x mod 2 = x mod 2)
sk_mod2 = np.concatenate([s_mod2, [1]]).astype(np.int64) & 1
# Decrypt each bit
bits = []
for row in ct:
    bit = int(np.sum(sk_mod2 * (row & 1)) & 1)
    bits.append(bit)

bitstr = "".join(str(b) for b in bits)
print(f"{len(bits)} bits")
val = int(bitstr, 2)
flag = long_to_bytes(val)
print(flag)
