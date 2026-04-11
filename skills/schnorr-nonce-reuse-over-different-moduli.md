---
name: schnorr-nonce-reuse-over-different-moduli
description: Schnorr nonce `v` reused across proofs under DIFFERENT primes still leaks the witness via an integer-lift equation — the mod wraps by exactly one (p_i - 1) when `c*w > v`.
type: feedback
---

Standard "Schnorr nonce reuse" is: two proofs with the same commitment `a = g^r` over the same group let you solve `w = (z_1 - z_2)/(e_1 - e_2) mod q`. That's Special Soundness and it's easy.

The less obvious variant: the prover reuses `v` (hence `a = g^v mod p`) across proofs under **different primes p_1, p_2** each with its own `q_i = p_i - 1` as the exponent modulus. Each call still gives:
```
r_i = (v - c_i * w)  mod (p_i - 1)
```
with the SAME integer `v` but different `p_i - 1`. You can't directly CRT across different moduli here — but you don't need to, because `v - c_i * w` is a specific integer whose reduction mod `(p_i - 1)` follows a predictable pattern.

**Key observation:** in the challenge I hit this on (Let's Prove It Again), `v` is ~512 bits and `c_i * w` is ~568 bits (c_i = 256-bit hash, w = 312-bit padded flag). So `v - c_i * w` is always NEGATIVE, and since its absolute value is far smaller than `p_i - 1` (~1024 bits), the Python `%` adjusts by exactly ONE wrap:
```
r_i = v - c_i * w + (p_i - 1)              (over Z, no mod)
⇒  v = r_i + c_i * w - (p_i - 1)           (over Z)
```

Equating two proofs with the same `v`:
```
r_1 + c_1 * w - (p_1 - 1)  =  r_2 + c_2 * w - (p_2 - 1)
(c_1 - c_2) * w = (r_2 - r_1) + (p_1 - p_2)
w = ((r_2 - r_1) + (p_1 - p_2)) / (c_1 - c_2)   [exact integer division]
```

So two proofs, each with a KNOWN p (force this by controlling the `refresh(seed)` entry into getPrime), are enough to recover w. `c_i` is just a hash of publicly-known stuff, possibly with a small bruteforce over one hidden byte per call.

**How to apply when you see `self.v` set once and reused:**
1. Confirm sizes: if `|v| + |c * w| < |p - 1| * 2`, the "off by one p-1 wrap" assumption holds.
2. Get two proofs where you control the PRNG seed feeding the prime generation (usually via a `refresh(seed)` option the challenge exposes). Reproduce both primes locally.
3. Apply the integer equation directly. Verify `y_1 == g^w mod p_1` to catch sign/wrap mistakes.
4. Flag decode: the challenge may wrap the plaintext with noise (e.g., insert a random non-printable byte at an unknown position, XOR middle bytes with a nonce). `long_to_bytes(w)` gives you the raw integer; strip the non-printable and verify the byte layout matches the stated format before declaring the attack failed.

The general insight is: "different moduli" doesn't stop you if the underlying integer relation is consistent and the bit budget works out. Always check whether the mod reduction actually reduces anything before giving up.
