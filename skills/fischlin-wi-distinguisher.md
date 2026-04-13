---
name: fischlin-wi-distinguisher
description: Fischlin OR proof WI 구별자: RO hit count로 b=0/1 판별. count>1이면 b=1 확실, count==1이면 b=0 추정(73%)
type: skill
---

# Fischlin Transform — WI Distinguisher via RO Hit Count

## When to use
- Fischlin-transformed OR proof where server holds b ∈ {0,1} and you know w0 (not w1)
- Server gives you a Fischlin proof and asks you to distinguish which witness was used
- The proof has an "e-search loop" that stops at first RO hit below threshold 2^(512-B)

## Key Insight: WI break via search position

In `fischlin_proof(w0, w1, y0, y1, b)`:
- If `b=0` (using w0): e1 fixed, loop searches e ∈ [0..1023] for first RO hit, sets e0 = e XOR e1
- If `b=1` (using w1): e0 fixed, loop searches e ∈ [0..1023] for first hit, sets e1 = e XOR e0

**Detection**: given the proof (e0, e1, z0, z1, e_proof), simulate what would happen if b=0:
```python
r_cand = (z0 - e0 * w0) % q
count_b0 = 0
for e_prime in range(e_proof + 1):
    z0_prime = (r_cand + (e_prime ^ e1) * w0) % q
    if RO(a0, a1, e_prime, e_prime ^ e1, e1, z0_prime, z1) < 2**(512 - B):
        count_b0 += 1
```

- If `b=0`: the actual `e'=e_proof` is exact match → count_b0 = **1 always**
- If `b=1`: z0_prime values are garbage → each hits with independent prob 1/64 → **count_b0 > 1 with high probability** when e_proof is large

## Strategy

```python
# count > 1 → definitely b=1
# count == 1 → ambiguous (probably b=0 but not certain)
if count_b0 > 1:
    guess = 1
else:
    guess = 0  # 73% correct on ambiguous rounds
```

Handle across 64 rounds. For 16 attempts per round:
- Most rounds resolved decisively (count > 1 → b=1, or early decisive)
- ~2% of rounds all-16-ambiguous → guess b=0 (73% chance correct per such round)
- ~12% failure rate per 64-round run → retry up to 10x

## Parameters to know

```python
B = 6         # RO threshold: 2^(512-B) = 2^506
e_range = 1024  # e searched in [0..1023]
numrounds = 64
attempts_per_round = 16
```

## Why this works

Fischlin replaces the interactive challenge with a proof-of-work search. The search structure exposes WHICH witness was used through the search depth (e_proof). If the simulated b=0 hits only once at position e_proof, b=0 was used. Multiple hits means b=0 simulation is wrong → b=1.

## Challenges
- CryptoHack CTF Archive: Fischlin's Transformation — `crypto{fishy_fischlin_www.youtube.com/watch?v=tL6dcQEY62s}`
