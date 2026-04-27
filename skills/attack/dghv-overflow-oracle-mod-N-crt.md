---
name: dghv-overflow-oracle-mod-N-crt
description: DGHV/AGCD scheme `c = p*q + N*r + m` with attacker-chosen N and a (c%p)%N decrypt oracle. Repeated additions overflow the inner mod-p so decrypt yields ((k+1) - j*p) mod N; the non-+1 step in consecutive decrypts equals (1 - p mod N) mod N, leaking p mod N exactly. Sweep N over coprime values (primes in the allowed range) and CRT to recover p — bypasses the η-ρ-tight lattice attack entirely.
type: attack
---

# DGHV / AGCD overflow oracle → CRT recovery of p

## When this fires

- DGHV-style somewhat-homomorphic scheme: `c = p*q + N*r + m` with `decrypt(c) = (c % p) % N`.
- Attacker can pick `N` (per session/encryption) and choose `m`.
- Attacker can issue a homomorphic-add of fresh ciphertexts (each adds independent `r_i`) and call decrypt on the cumulated ciphertext.
- The η-ρ gap (size of p vs. size of N*r noise) is small — typically ρ ≈ η - 2 — so the standard AGCD lattice (Howgrave-Graham/Galbraith) needs many more samples than the oracle gives. **Don't waste time on lattice; the oracle gives p exactly.**

This is the path used in CSC Belgium 2024 "Additional problems" (CryptoHack archive). p was 128-bit, N constrained to [128, 256), `r < 2^128/N/4` so N*r < 2^126.

## Why it works

After action-1 (encrypt one byte, m=1) and `k` action-2's (each adds another encryption of m=1):
```
c = p*Σq_i + N*Σr_i + (k+1)
T := N*Σr_i + (k+1)
decrypt = T mod p mod N = (T - j*p) mod N      where j = floor(T/p) ∈ {0,1,2,...}
```
Because `N | N*Σr_i`, `(T - j*p) mod N = ((k+1) - j*p) mod N`.

Per-step Δj ∈ {0, 1} when one fresh r (size N*r < p) is added. So the consecutive diff is either:
- **+1** (mod N) — no new overflow (Δj=0)
- **(1 - p mod N) mod N** — exactly one new overflow (Δj=1)

Pick the most common non-1 diff and `p mod N = (1 - that_diff) mod N`. Done — no rounding ambiguity, no lattice.

## Procedure

1. Find the largest set of pairwise-coprime N values in the allowed range. **Primes are perfect** — they're trivially coprime and dense enough. For range [128, 255] you get 23 primes whose product is ~2^184 (more than enough to uniquely pin a 128-bit p).
2. For each prime N: action-1 with m=`b'\x01'`, then `K` rounds of (action-2 + decrypt). Collect decrypt outputs.
3. Recover `p mod N` from non-+1 diffs (Counter most-common).
4. CRT the residues. As soon as the modulus product exceeds ~140 bits, you're done.
5. Decrypt the supplied flag ciphertexts: `flag[i] = (c_i % p) % 128`.

## Choosing K

Per-step contribution to T: `N*r_new ≈ p/4` on average (since `r_max = 2^128/(N*4)` and `N*r ≤ 2^126 ≈ p/4`). So the first overflow appears around k+1 ≈ 4, then ~every 4 steps after that.

K=15 gives ~3 overflows per N — more than enough to pick the majority diff. K=10 cuts time and still works in practice but miss-rate goes up.

## Quirks that bite

- **First inner-loop iteration is special**: the typical CTF server `Game` skips the action-menu prompt on the first iteration (forces action="new"). Calling `sendlineafter(b"     > ", b"1")` on first iter hangs. Pass a `first=True` flag and skip that send.
- **Don't pipeline** action commands. The server's `recv(1024).strip()` collapses any multi-line batch into a single string and `int(...)` fails. Use `sendlineafter` per prompt.
- **N=128 (=2^7)** also works as an oracle and gives `p mod 128`, but adds only 7 bits and overlaps coprime-wise with nothing useful — primes only is cleaner.
- **rmax = 2**128 / N / 4** is a `float` in Python 3. Modern Python's `random.randint(0, float)` raises `TypeError`. The challenge server presumably runs Python ≤ 3.10 where this still works (with deprecation). Don't be confused if local repro on 3.12 crashes — the math is identical, just call `int(rmax)`.

## Don't confuse with

- **AGCD / Howgrave-Graham lattice**: applies when you have many `c_i = p*q_i + s_i` *visible* and η-ρ gap is wide enough. Here the gap is 2 bits and only the flag's ~36 ciphertexts are visible — lattice fails.
- **Approximate-GCD pairwise**: `gcd(c_i - m_i, c_j - m_j)` doesn't recover p because the noise terms `N*r_i, N*r_j` aren't multiples of p.

## Companion files

- Reference solve: `cryptohack/CTF Archive/2024/Additional problems (CSC Belgium)/solve.py`
- Local oracle simulation (validates the diff logic without a server): `solve.py`'s `recover_p_mod_N` is small enough to inline; for offline test, mock `dghv_encrypt`/`dghv_decrypt` directly.
