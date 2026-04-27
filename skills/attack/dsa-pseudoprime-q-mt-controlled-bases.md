---
name: dsa-pseudoprime-q-mt-controlled-bases
description: Forge DSA when os.urandom is replaced by random.randbytes BEFORE Crypto.* import — predictable MR bases let you smuggle a composite q (Lucas pseudoprime + Carmichael-like) past PyCryptodome's primality. Combined with TSG "This is DSA" trick (g of order = smallest factor of q) → DLP becomes trivial.
type: attack
---

# Forging DSA via predictable MR bases + composite q

## Trigger
- `os.urandom = random.randbytes` (or equivalent) executed **before** `from Crypto.* import ...`. Then `Crypto.Random.urandom = random.randbytes` after the patch propagates through the import.
- `random.seed(seed)` controlled by attacker → deterministic MT state → all `Crypto.Random.urandom(n)` outputs are predictable.
- DSA parameter set (q, p, g) chosen by attacker, validated only via `DSA.construct(...)` (default `consistency_check=True`).
- Server only verifies (or signs locally with attacker-controlled `x` after key construction).

## Why PyCryptodome's primality test cracks
`test_probable_prime(n)` does:
1. **Trial division**: `map(n.fail_if_divisible_by, _sieve_base)` — **lazy iterator never consumed**, this is a no-op (PyCryptodome bug).
2. **Miller-Rabin**: `mr_iterations` rounds (160-bit → 30, 224/256 → 20, 1024 → 4, 2048+ → ≤3). Bases drawn via `Integer.random_range(2, n-2, randfunc=Random.new().read)` — RNG controllable.
3. **Lucas test**: Selfridge's Method A, **deterministic**. The killer for naive composites.

Naive Carmichael (Arnault `n=p1p2p3` MR-pseudoprime) **fails Lucas**. Naive Lucas-pseudoprime construction (P&P paper §3.2.1) has near-zero MR liar fraction. Combining MR + Lucas pseudoprime in one number is "hard" per the P&P paper.

## The trick: pseudoprime form that passes BOTH
From "Prime and Prejudice" §3.2.1 (Albrecht et al. 2018):
- `q = p1 * p2 * p3` with `p2 = k2(p1+1) - 1`, `p3 = k3(p1+1) - 1`, `k2, k3` odd, `gcd(k2, k3) = 1`.
- `p1 ≡ 7 (mod 20)`, `p2 ≡ p3 ≡ 2 or 3 (mod 5)`.
- `p1 ≡ k3⁻¹ (mod k2)`, `p1 ≡ k2⁻¹ (mod k3)`.
- This passes Lucas-Selfridge.
- For MR (controlled bases), additionally check `Z(1).nth_root((q-1)/2, all=True)` has ≥ 2 elements (so a non-trivial sqrt of 1 exists). Use `a = Z(1).nth_root((q-1)/2)` (a non-trivial fourth-root-of-unity-like element). Then **`a` is a strong liar** for q (because `a^((q-1)/2) ≡ 1 (mod q)` and `a ≢ ±1`).
- Force ALL 30 MR bases to equal `a` via Z3 inversion of MT19937 state.

## Skipping the Pohlig-Hellman cost: order-`q1` generator (TSG "This is DSA" trick)
- Let `q1 = smallest prime factor of q` (~40 bits in 160-bit q).
- Pick `p` (real prime, 1024-bit) with `q | (p-1)`.
- Set `g = h^((p-1)/q1) mod p` for some h, ensuring `g ≠ 1` and `g^q1 ≡ 1 mod p`.
- Construct check `pow(g, q, p) == 1` still passes because `q1 | q`, so `g^q = (g^q1)^(q/q1) = 1`.
- `y = g^x mod p` only depends on `x mod q1` (since `ord(g) = q1`). Recover via `Zmod(p)(y).log(g)` in Sage — Pohlig-Hellman in 40-bit prime → seconds.
- Use `x_eff = x mod q1` as private key. Verify equation only depends on `x mod ord(g) = x mod q1`, so signature is valid.

## Forcing 30 MR bases = `a` via MT seed inversion
`Integer.random_range(2, q-2, randfunc=urandom)` calls `Integer.random(max_bits=bits, randfunc=urandom)`:
- For 160-bit q: 1 byte first, then 19 bytes (152 bits = 4 × 32-bit MT outputs + 24 high bits of 5th).
- Per base: ~5 32-bit MT outputs to control + the rejection-sampling first byte (only need it < `q`'s top byte).
- For 1024-bit p (4 MR rounds): 1 byte + 127 bytes = ~32 outputs each.

Use a Z3 model of MT19937:
1. Express `untemper(rand_i) = next_state_i` as bitvector constraints for desired outputs.
2. Solve for `state[i]`.
3. Then express `init_by_array(seed, key_length)` symbolically and constrain to recovered state. Solve for seed bytes.

See y011d4's official `find_seed.py` for full Z3 model (state[0] = 0x80000000 fixed; iterate update_mt; constrain `next_state[i] == untemper(rands[i])`; solve; then invert `random_seed` via second solve).

## Concrete numbers (y011d4 official sol; reusable since seed is independent of `x`)
```
q = 898886696987234192216203179809052471733122879407   # 160-bit, p1*p2*p3
a = 863882519526477315572070417818352889307249769025   # strong-liar element
p = (1024-bit prime with q | p-1)
g = (order q1 = factor(q)[0][0] ≈ 40-bit prime)
seed_int = (long hex precomputed via Z3 to force 4×128-byte + 30×20-byte sequences)
```

## Solver outline
```python
import os, random
os.urandom = random.randbytes              # MUST be before any Crypto import
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

io = remote(...)
io.sendlineafter(b"q = ", str(q).encode())
io.sendlineafter(b"p = ", str(p).encode())
io.sendlineafter(b"g = ", str(g).encode())
io.sendlineafter(b"hex): ", hex(seed_int).encode())
y = int(io.recvline_after(b"y = "))
x = int(Zmod(p)(y).log(g))                 # PH on q1 (~40-bit)
random.seed(seed_int)                      # for dss.sign internal RNG
dsa = DSA.construct((y, g, p, q, x))       # passes b/c MR sees `a` 30×, Lucas passes by construction
dss = DSS.new(dsa, "fips-186-3")
sign = dss.sign(SHA256.new(b"sign me!"))
io.sendlineafter(b"sign = ", sign.hex().encode())
```

## Pitfalls
- **Import order matters**: patch `os.urandom` BEFORE the FIRST `from Crypto.Random ...` (direct or transitive). Otherwise `Crypto.Random.urandom` is the real `os.urandom`.
- **Lucas test is deterministic** — no amount of seed control fools it. Must construct `q` from §3.2.1 form; otherwise it fails.
- **Fipscheck on (L, N)**: must be one of `{(1024,160),(2048,224),(2048,256),(3072,256)}`. With 160-bit q, 30 MR rounds (≤220-bit gets 30; 220–280 bit gets 20).
- `random.seed` must be re-applied before `dss.sign` because `dss.sign` calls `Crypto.Random` for nonce; the same seed_int that the server uses also drives our local sign — but **after** the server has already consumed bytes for primality testing, so we re-seed locally for signing.
- For dss.sign to work with `x = x mod q1` (composite q), DSA.construct's `pow(g, x, p) != y` check passes because `y = g^x mod p = g^(x mod q1) mod p`.

## References
- "Prime and Prejudice: Primality Testing Under Adversarial Conditions" Albrecht, Massimo, Paterson, Somorovsky (CCS 2018) — §3.2.1 Lucas-pseudoprime construction.
- TSG CTF 2021 "This is DSA" — `p = q^k` linearization (variant: `g` of order = small factor).
- SECCON CTF 2022 "janken vs kurenaif" — MT19937 seed inversion via Z3.
- HackTM CTF 2023 "unrandom DSA" by y011d4 — combines all three.
