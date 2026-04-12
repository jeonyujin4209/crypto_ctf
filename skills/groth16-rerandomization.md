# Groth16 Proof Re-randomization (Malleability)

## When to use
- Server accepts Groth16 proofs and gives rewards per unique proof
- You have one valid proof (A, B, C) and need many distinct valid proofs
- Challenge involves farming credits via unique ticket/proof IDs

## The Attack

For any valid Groth16 proof (A ∈ G1, B ∈ G2, C ∈ G1) and random scalar λ:

```
A' = λ^{-1} · A    (G1 scalar multiply)
B' = λ · B         (G2 scalar multiply)
C' = C             (unchanged)
```

Then `e(A', B') = e(λ^{-1}·A, λ·B) = e(A, B)` by bilinearity of pairing.
So (A', B', C') satisfies the same verification equation → valid proof.

Different bytes → different ID (e.g., blake2 hash of proof bytes) → redeemed independently.

## Serialization (arkworks BN254 compressed format)

```python
# G1 point (32 bytes, little-endian)
# byte[31] bit7 = POSITIVE_Y flag (1 if y <= (p-1)/2)
# byte[31] bit6 = INFINITY flag

# G2 point (64 bytes = c0 || c1, each 32 bytes LE)
# c1[31] bit7/bit6 = same flags

# IMPORTANT: mask with 0x3F (not 0x1F!) when reading coordinates
x_val = int.from_bytes(compressed[:32], 'little') & 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```

## Implementation sketch

```python
from py_ecc.bn128 import G1, G2, multiply, add, neg, field_modulus

def decompress_g1(data: bytes) -> tuple:
    flags = data[31] >> 6
    x = int.from_bytes(data, 'little') & ((1 << 254) - 1)
    # recover y from x and flag...

def rerandomize(A_bytes, B_bytes, C_bytes, lam: int):
    A = decompress_g1(A_bytes)
    B = decompress_g2(B_bytes)
    lam_inv = pow(lam, -1, curve_order)
    A2 = multiply(A, lam_inv)
    B2 = multiply(B, lam)
    return compress_g1(A2), compress_g2(B2), C_bytes  # C unchanged
```

## Economics example (Ticket Maestro)

```
BALANCE=10, COST_FLAG=20, COST_TICKET=2, VALUE_TICKET=1
Plan:
  1. Buy 1 ticket → balance = 8
  2. Redeem 1 original + 12 re-randomized → balance = 8+13 = 21
  3. Buy flag ✓
```

Need: 12 valid re-randomizations from 1 proof, each with distinct λ.

## Pitfalls
- arkworks uses LE byte order (NOT BE like py_ecc default)
- Mask bits: 0x3F for G2 coordinates, not 0x1F
- G2 has TWO field elements (c0, c1); flags are in c1's high byte
- C stays the SAME in all re-randomizations — only A and B change

## Challenges
- CryptoHack CTF Archive: Ticket Maestro — `crypto{m4ll34b1l1ty_fl4w_0r_r3r4nd0m1s4t10n_f34tur3?}`
