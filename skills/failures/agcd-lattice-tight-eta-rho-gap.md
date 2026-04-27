---
name: agcd-lattice-tight-eta-rho-gap
description: AGCD/DGHV lattice attack (Galbraith/Howgrave-Graham) needs t > γ/(η-ρ) samples. When η-ρ is tiny (≤2 bits), required t is hundreds — even BKZ-20 on dim 60-70 won't find the q-target. Don't burn cycles on lattice when sample count is bounded by problem structure (e.g., flag length ~36); look for an oracle/structural leak instead.
type: failure
---

# AGCD lattice fails when η-ρ gap is tight and samples are bounded

## Symptom

Given many `c_i = p*q_i + s_i` with `|s_i| < 2^ρ`, you set up the standard lattice:
```
B = | 2^ρ   c_1   c_2  ...  c_{t-1} |
    | 0   -c_0    0   ...     0    |
    | 0    0    -c_0  ...     0    |
    ...
```
LLL or BKZ runs without error. First row's `v[0]/S` looks "kind of" the right size (close to log2(q) ≈ γ-η bits). But computing `p_guess = round(c_0 / q_0)` gives a number off by hundreds of bits, and `(c % p_guess) % N` decrypts to garbage.

This is what happens when η-ρ is too small for the chosen t.

## Why

LLL's quality factor is ~`2^((t-1)/4)`. For the q-target to be the shortest vector in the lattice, you need:
```
target_norm ≈ √t · 2^(γ-η+ρ)   <   2^((t-1)/4) · det(L)^(1/t)
```
With det ≈ `2^(ρ + γ(t-1))`, plugging in gives the rough criterion
```
t > γ / (η - ρ) + O(log t)
```
- η-ρ = 30 bits, γ = 1024 → t ≈ 35 (very feasible)
- η-ρ = 10 bits, γ = 1024 → t ≈ 105 (borderline LLL, OK with BKZ-20)
- η-ρ = 2 bits,  γ = 1152 → t ≈ 576 (need hundreds of samples; LLL/BKZ won't help with t=60-70)

Flag-length problems (CryptoHack-style: 30-80 ciphertexts visible at connect, no extra `c` exposure) are stuck at t ≤ flag_len. If flag_len is 36-66 and η-ρ ≤ 2, **the lattice is mathematically borderline and the LLL/BKZ approximation factor pushes it over.**

## Concrete failure case

CSC Belgium 2024 "Additional problems": p = 128-bit prime, N*r ≤ 2^126, so η=128, ρ=126, γ=1152. Flag length = 36.

- LLL on dim-66 lattice (with fake-flag local test): runs fast, but `v[0]/S` produces `q0` of 993 bits (vs. true 1024) and `p_guess` differs from `p_true` by hundreds of bits.
- BKZ-20 doesn't fix it — the lattice **doesn't contain a short enough q-target relative to its determinant**.

## Decision rule

Before committing to AGCD lattice, compute:
```
required_t ≈ γ / (η - ρ)
```
If `required_t > available_samples × 1.5`, **don't try lattice**. Look for:
1. An oracle that leaks `p mod N` or `p mod something` directly (overflow oracle, low-bit leak via decryption with attacker-chosen modulus)
2. A different protocol abuse path (homomorphic add → overflow, malleability, etc.)
3. Some other structure in `q`, `r`, or `m` (e.g., predictable RNG, repeating sub-blocks)
4. ONLY if none of these: collect more samples (multiple connections may help if same `p` persists, but typically not — each connection regens p).

## What to NOT do (wastes time)

- "Maybe BKZ block size 30 will fix it" — no, it won't if the lattice fundamentally doesn't have the target as shortest vector
- "Try different `S` scaling factor" — affects constants, not asymptotic feasibility
- "Use more lattice rows" — when bounded by flag length / ciphertext count, this isn't an option
- "Try Coppersmith multivariate" — same fundamental gap problem; doesn't change the math

## Companion files

- Reference solve via overflow oracle (the right approach for tight η-ρ): `cryptohack/CTF Archive/2024/Additional problems (CSC Belgium)/solve.py`
- Companion attack skill: `attack/dghv-overflow-oracle-mod-N-crt.md`
