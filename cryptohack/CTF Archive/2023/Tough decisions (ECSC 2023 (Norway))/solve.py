"""
Tough decisions (ECSC 2023, contributed by CryptoHack)

VULNERABILITY:
- LWE-style decision oracle. Each flag bit produces 6 samples.
  - real(s): a random, b = <a,s> + e (mod 256), e = sample_noise(7) - 64.
  - fake(s): a random, b uniform in [0,256).
- BUG: sample_noise(7) does `e |= bit; e <<= 1` so the LAST shift always
  empties the LSB → e is always EVEN. Then e - 64 is also even.
- Therefore for real rows: b ≡ <a,s> (mod 2)  (NO noise mod 2).
  For fake rows: b mod 2 is uniform.
- This reduces to a clean Binary LWE problem mod 2 with 128 unknowns
  (LSBs of each byte of the 16-byte key s) and rows split into
  "all-6-consistent" (real) vs "random" (fake).

ATTACK:
- Treat each sample as one linear eq mod 2 over the 128 bits of s.
- Real rows give 6 always-satisfied equations; fake rows give random.
- Information-set-decoding-like: randomly pick 22 rows (132 eqs),
  assume all real, Gauss-eliminate over GF(2). Verify by counting
  how many rows have ALL 6 equations satisfied (real → always; fake → 1/64).
- Probability 22 rows all real = 2^-22; but many trials cheap (numpy).
- Once s is recovered, classify each row: real ↔ all 6 satisfied, then
  the flag bit is 0 for real, 1 for fake.
"""

import ast
import os
import sys
import numpy as np

random_seed = 0xC0FFEE

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_output(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(ast.literal_eval(line))
    return rows


def row_to_eqs(row):
    """Each row: list of (a_bytes, b_int). Returns (A, B) over GF(2):
    A is (6, 128) matrix of LSBs of each bit of a, B is (6,) vector of b mod 2.
    Wait - actually a is bytes vector and we take dot product. But we only care
    mod 2. dot(a, s) mod 2 = sum_i a_i * s_i mod 2. With a_i and s_i being bytes,
    a_i * s_i mod 2 = (a_i mod 2) * (s_i mod 2). So we use LSB of a_i and LSB of s_i.
    """
    A = np.zeros((6, 16), dtype=np.uint8)
    B = np.zeros(6, dtype=np.uint8)
    for i, (a_bytes, b) in enumerate(row):
        for j in range(16):
            A[i, j] = a_bytes[j] & 1
        B[i] = b & 1
    return A, B


def gf2_solve(A, b):
    """Solve A x = b over GF(2). A: (m, n) with m >= n. Returns x (n,) or None."""
    m, n = A.shape
    M = np.concatenate([A, b.reshape(-1, 1)], axis=1).astype(np.uint8) % 2
    row = 0
    pivots = []
    for col in range(n):
        # find pivot
        piv = None
        for r in range(row, m):
            if M[r, col]:
                piv = r
                break
        if piv is None:
            continue
        M[[row, piv]] = M[[piv, row]]
        for r in range(m):
            if r != row and M[r, col]:
                M[r] ^= M[row]
        pivots.append(col)
        row += 1
        if row == n:
            break
    # check consistency: rows with no pivot must have rhs = 0
    for r in range(row, m):
        if M[r, n]:
            return None
    # check rank = n
    if len(pivots) < n:
        return None  # underdetermined, skip
    # extract solution
    x = np.zeros(n, dtype=np.uint8)
    for r, c in enumerate(pivots):
        x[c] = M[r, n]
    return x


def main():
    output_path = os.path.join(HERE, "output.txt")
    rows = parse_output(output_path)
    print(f"[*] Parsed {len(rows)} rows")

    # Build A and B per row
    row_A = []
    row_B = []
    for r in rows:
        A, B = row_to_eqs(r)
        row_A.append(A)
        row_B.append(B)
    row_A = np.array(row_A)  # (R, 6, 16)
    row_B = np.array(row_B)  # (R, 6)
    R = len(rows)

    # Prepare full equation matrix at sample level
    # Each row contributes 6 eqs over 128 vars (16 bytes * 8 bits? NO — only LSB matters!)
    # Wait: dot(a, s) mod 2 = sum_j (a_j mod 2) * (s_j mod 2). So 16 unknowns total!
    # Each unknown is the LSB of one byte of s.
    #
    # So we only need 16 equations, not 128! Far easier.
    #
    # Pick subsets of 3 rows = 18 eqs > 16 vars. Probability all real = 1/8.
    # Even pick 1 real row → 6 eqs, plus a 2nd real row → 12 eqs, plus 1 more eq from a 3rd real.
    print("[*] Only 16 unknowns (LSB of each byte of s). Trying small random subsets.")

    rng = np.random.default_rng(random_seed)

    target_eqs = 32  # over-determined
    best_s = None
    best_score = -1

    for trial in range(200000):
        # pick 6 rows; 36 equations
        idxs = rng.choice(R, size=6, replace=False)
        A_stack = np.concatenate([row_A[i] for i in idxs], axis=0)  # (36, 16)
        B_stack = np.concatenate([row_B[i] for i in idxs], axis=0)
        sol = gf2_solve(A_stack, B_stack)
        if sol is None:
            continue
        # verify on all rows: count rows where all 6 eqs satisfied
        # res[i, j] = (row_A[i,j] @ sol) ^ row_B[i,j]
        proj = (row_A @ sol.astype(np.int64)) % 2  # (R, 6)
        match = (proj == row_B)  # (R, 6) booleans
        all_match = match.all(axis=1)  # (R,)
        score = all_match.sum()
        if score > best_score:
            best_score = score
            best_s = sol.copy()
            print(f"  trial {trial}: score={score}/{R}")
            if score >= R // 3:  # roughly half should match (real rows)
                break

    print(f"[*] Best s LSBs: {best_s}, matching rows: {best_score}/{R}")

    # classify each row: real (all 6 eqs match) -> bit 0, fake -> bit 1
    proj = (row_A @ best_s.astype(np.int64)) % 2
    match = (proj == row_B)
    all_match = match.all(axis=1)
    bits = (~all_match).astype(int).tolist()

    # Reconstruct flag: bits per byte are flag[bit_index] = (b >> i) & 1, i=0..7
    assert len(bits) % 8 == 0, f"bits length {len(bits)} not multiple of 8"
    flag = bytearray()
    for byte_i in range(len(bits) // 8):
        b = 0
        for i in range(8):
            b |= bits[byte_i * 8 + i] << i
        flag.append(b)
    print(f"[*] Flag: {bytes(flag)!r}")


if __name__ == "__main__":
    main()
