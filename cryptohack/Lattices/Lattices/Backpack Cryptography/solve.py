"""
Merkle-Hellman knapsack cryptosystem attack using LLL (python-flint).
"""
import json
from flint import fmpz_mat

# Read output
with open("C:/Users/SECUI/Documents/crypto_ctf/cryptohack/Lattices/Lattices/Backpack Cryptography/output.txt") as f:
    content = f.read().strip()

# Parse
pk_start = content.index('[')
pk_end = content.index(']') + 1
public_key = json.loads(content[pk_start:pk_end])

ct_line = content[pk_end:].strip()
encrypted = int(ct_line.split(': ')[1])

n = len(public_key)
print(f"Number of bits: {n}")

# CJLOSS lattice: (n+1) x (n+1)
# Rows 0..n-1: 2*I with last column = a_i
# Row n: all 1s with last column = encrypted
N = n + 1
rows = []
for i in range(n):
    row = [0]*N
    row[i] = 2
    row[n] = public_key[i]
    rows.append(row)
last_row = [1]*n + [encrypted]
rows.append(last_row)

mat = fmpz_mat(rows)
print("Running LLL...")
reduced = mat.lll()
print("LLL done")

# Look for a row where last element is 0 and all other elements are +/-1
for i in range(N):
    row = [int(reduced[i, j]) for j in range(N)]
    if row[-1] == 0:
        bits = row[:-1]
        if all(b in (1, -1) for b in bits):
            for sign in [1, -1]:
                msg_bits = [(1 - sign*b) // 2 for b in bits]
                if all(b in (0, 1) for b in msg_bits):
                    # Source encrypts LSB first
                    msg_int = sum(b << i for i, b in enumerate(msg_bits))
                    try:
                        flag = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
                        if b'crypto' in flag:
                            print(flag.decode())
                    except:
                        pass
