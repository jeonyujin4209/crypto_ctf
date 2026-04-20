# Paillier Homomorphic Carry Oracle (Fingerprinting)

type: attack
tags: [paillier, padding-oracle, homomorphic, non-adaptive, fingerprint]

## When to use

- Paillier encryption with PKCS#1-like padding (header + non-zero padding + \x00 separator + message)
- Oracle reveals valid/invalid padding (binary response)
- Non-adaptive queries: must submit all queries at once, then receive all responses
- Secret has low entropy (brute-forceable candidate set)

## Key Insight

Paillier additive homomorphism: `E(m) * g^delta mod n^2 = E(m + delta mod n)`.

Plaintext structure: `\x00\x02 | random_padding (no \x00) | \x00 | secret`

Adding delta to the 128-byte secret zone causes **carry into the separator byte**:
- No carry: separator stays \x00 → unpad always succeeds (happy)
- Carry: separator becomes \x01 → unpad succeeds only if remainder has a \x00 byte

In the **all-carry zone** (delta chosen so carry occurs for ALL candidates), the oracle cleanly tests:
```
oracle_happy ⟺ has_zero_byte((S + delta) mod 256^128)
```

Different deltas produce different zero-byte patterns → 20 queries create a unique fingerprint per candidate.

## Delta Range

```python
BYTE128 = 256 ** 128
delta_lo = BYTE128 - s_min   # ensures carry for smallest S
delta_hi = 2 * BYTE128 - s_max  # prevents double-carry for largest S
```

**Critical**: Using `[BYTE128 - s_max, BYTE128 - s_min]` (mixed zone) is WRONG — many candidates won't carry, all getting trivial "happy" responses.

## Statistics

- P(has_zero_byte for random 128 bytes) ≈ 1 - (255/256)^128 ≈ 39.4%
- 20 queries → ~88% unique fingerprints among 65536 candidates
- P(correct per round) ≈ 0.91, P(16 rounds) ≈ 0.22
- Expected ~5 connection attempts to succeed

## Algorithm

1. Precompute all candidate S values from secret's entropy source
2. Choose 20 random deltas in the all-carry zone
3. Build fingerprint table: for each candidate, compute 20-bit fingerprint
4. For each round: send `c0 * pow(g, delta, n^2) % n^2` for each delta
5. Parse responses into fingerprint, look up in table
6. If collision: guess randomly among candidates sharing that fingerprint
7. Retry connection if any round fails

## Gotchas

- **All-carry zone is essential**: mixed zone gives ~36% unique (useless); all-carry gives ~88%
- `has_zero_byte` depends on full carry-propagation chain across 128 bytes — complex, non-linear
- For the oracle model to work, delta must not affect bytes above the separator (keep delta < 2*BYTE128)
- pwntools `log.error()` raises an exception — use `log.warning()` for non-fatal failures
