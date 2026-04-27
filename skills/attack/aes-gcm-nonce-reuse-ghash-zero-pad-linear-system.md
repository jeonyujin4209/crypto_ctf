---
name: aes-gcm-nonce-reuse-ghash-zero-pad-linear-system
description: AES-GCM tag forgery via fixed (K, IV) and zero-padded short blocks. Recover both H = E_K(0) and S = E_K(J0) from many observed tags by setting up a GF(2)-linear system; the 32 zero pad bits per 12-byte input block give known-bit constraints that turn the GF(2^128) polynomial mess into solvable linear algebra.
type: attack
---

# AES-GCM nonce reuse + zero-pad linear system

## When this fires

- AES-GCM oracle reuses key K and nonce IV across many tag queries
- Server input chunks are SMALLER than the GHASH block size (typically 12 bytes per chunk → padded to 16 with 4 zero bytes ⇒ 32 known zero bits per data block)
- You can issue tag queries where AAD and/or CT bytes are unknown to you (random server-side) but their LENGTHS are something you can drive
- Final goal is a one-shot tag forgery for a *different* AAD/CT (e.g., predict tag of empty message)

This is the family used in CODEGATE 2024's "Greatest Common Multiple". Soon Haari's writeup (https://soon.haari.me/gcm/) is the canonical reference.

## The two unknowns to recover

GHASH polynomial uses H = E_K(0). Tag for one AES-GCM call:
```
tag = GHASH(AAD_pad || CT_pad || L) ⊕ S    where S = E_K(J0)
```
Both H and S are 16-byte constants under fixed (K, IV). Recovering H lets you do polynomial arithmetic; recovering S lets you predict any tag.

Predicting the EMPTY-message tag is trivial once you have S: empty AAD/CT means GHASH input is just the all-zero length block, and tag = 0 ⊕ S = S.

## Step 1 — Recover H

Issue `~150` alternating `(u1, tag)` (or any operation that flips ONE block somewhere):

- Between two consecutive tags, exactly one of {AAD, CT} has one block REPLACED with fresh random.
- Tag diff: `D = (Δ_block) · y^k ⊕ (length-block-diff) · y` where `Δ_block` is the changed block's XOR difference.
- `k ∈ {2, 3, 4, 5}` depending on which slot was hit and how many AAD/CT blocks exist.

**Key trick**: `Δ_block` is the difference of two 12-byte plaintexts each padded with 4 zero bytes — so `Δ_block` has 32 known zero bits in fixed positions. Therefore `D · y^{-k} · a^{-32}` (in the GHASH bit-reverse representation) must have 96 high bits = 0 *iff k was the right exponent*. This gives 32 GF(2) equations on the 128 coefficient bits of `y^{-k}` per tag pair.

Stack 5 random tag-pair equations → 160 eqs in 128 vars over GF(2) → kernel typically 1-dimensional. Repeat with fresh 5-tuples until you collect TWO distinct kernel solutions (corresponding to `y^{-2}` and `y^{-3}`, the two slot-induced exponents). Pick `y` such that `y^{-3}` matches what `y^{-2}^{3/2}` would be, and you have H.

```python
# Per tag-pair, build 32 GF(2) equations on coefficients of y^{-k}.
dat_n = bytes_to_n(xor(tag_old, tag_new))
basis = [dat_n]
for _ in range(127):
    basis.append((basis[-1] << 1) ^^ (mod_int if basis[-1] >> 128 else 0))
# Take the top 32 bits AFTER multiplying by y^{-k} ... encoded as linear constraints
vecs = [vector(GF(2), [basis[j] >> (i + 96) for j in range(128)]) for i in range(32)]
```

## Step 2 — Recover S (and AAD/CT)

Now you can do polynomial arithmetic in GF(2^128). Set up a *big* GF(2) linear system relating UNKNOWN bits (AAD bytes + CT bytes + S bytes) to OBSERVED tag bits across many queries.

Procedure:
1. Reset both slots to 12 bytes each via many `u1` calls.
2. Drive AAD/CT lengths to grow predictably via `(u2, tag)` repeats. Each `u2` extends ONE of the two slots by 12 bytes (server-randomized which slot).
3. Detect which slot got hit each time. Specific patterns like `[1,1,1,0,0,0]` (3 CT-extensions then 3 AAD-extensions) bring the state to (ad=48, ct=48) — a CLEAN 3-block-each layout. Detection via the same zero-bit signature trick as Step 1, but applied to consecutive tag pairs whose hypothesized lengths predict block counts that DON'T change (so the diff polynomial has clean form).
4. Continue with `tag_n - 7` more `(u2, tag)` pairs. Brute-force over the unknown trailing slot pattern (`2^(tag_n - 7)` values).
5. For each candidate pattern, set up `tag_n × 128` GF(2) equations in `(AAD_bits + CT_bits + 128_S_bits)` unknowns. The TRUE pattern's matrix has minimum kernel dimension; wrong patterns either fail `solve_right` or have rank-deficient systems.
6. Enumerate the kernel (`2^kernel_size` candidates) — one matches the true (AAD, CT, S).

## Step 3 — Forge

Predicted tag for empty message = S directly (length block all zeros, no GHASH terms).

```python
# Send hex(S_bytes) as the final answer.
```

## Implementation notes that bite

- **GHASH bit order is bit-reversed** vs. polynomial-coefficient order. Use a `bytes_to_n` that does `int(f"{v:0128b}"[::-1], 2)` — without this, every multiplication is wrong by a bit-reverse.
- **Pre-compute `pre_mat[exp]`** as 128×128 GF(2) matrices where col k of `pre_mat[exp]` is the bit decomposition of `y^exp · a^k`. Then use SLICE assignment `M[r:r+128, c:c+128] = pre_mat[exp]` instead of nested per-bit Python loops. Speedup: ~20× on a 1500×1400 matrix.
- **Use `M.rank()` not `M.right_kernel().basis()` inside the brute-force loop** to test pattern validity. Compute the basis only for the final selected pattern. `rank()` is much cheaper than materializing kernel basis vectors.
- **Pick the pattern with MINIMUM kernel dimension** when multiple `it_full` brute-force values pass `solve_right`. Wrong patterns tend to have larger kernel due to partial linear dependencies.
- **Multiple candidates remain** (kernel often 2–4 dims, so 4–16 cands enumerate). On a one-shot oracle, pick `cand[0]` (the `solve_right` base solution); empirically the right one is `cand[0]` in many runs because Sage's `solve_right` returns a canonical minimum-weight-ish solution. Reconnect on failure.

## Don't confuse with

- **Forbidden Attack** (Joux / authentication-key recovery): same nonce-reuse premise but recovers H by finding multiple `(AAD, CT)` pairs producing the SAME tag — this requires CHOSEN AAD/CT, not just observed tags from server-controlled random data.
- **Direct length-block manipulation**: doesn't apply if the server hashes its own (random) AAD and CT. The exploit here is the ZERO PAD inside short data blocks, not direct ciphertext malleability.

## Companion files

- Reference solve: `cryptohack/CTF Archive/2024/Greatest Common Multiple (CODEGATE CTF)/solve.sage`
- Local-mode solve (with `DBG_S` cand verification): `solve_local.sage` in same dir
