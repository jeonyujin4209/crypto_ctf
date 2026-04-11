# LWE Primal Embedding — Kannan Target-Sign Trap

## 유형
LWE / lattice attacks where the secret S is full-range mod q but the noise
e is bounded (e.g., `e ∈ {-1, 0, 1}`). Typical setup: convert to a
"short-secret" instance by inverting the first n samples, then run
LLL/BKZ + Babai (or Kannan embedding) to recover the small secret.

## Trigger 패턴
- LWE with bounded noise (binary, ternary, or small bounded integers)
- Server gives many `(A_i, b_i)` with `b_i = A_i · S + e_i (mod q)`
- We compute `W` and `y` from a "short-secret" rewrite, then build a
  primal lattice + Kannan target embedding
- BKZ runs fine, returns ANYTHING that looks short, but verification of
  the recovered S against the original samples fails

## 왜 못 풀었나 (A)

### 잘못된 직관: "target = (0, -y), so embed row is (0, -y, K)"
The mental model: "I want lattice point ≈ target, so put target into the
embed row." Wrong by a sign. Kannan's formula:

```
B' = [ B  0 ]
     [ t  K ]
```

A vector in `L(B')` of the form `(b + 1·t, K)` is a single integer combo
that adds **+1·target_row** to a lattice element from B. The vector is
short iff `b ≈ -t`. **So Kannan finds the lattice point closest to −t,
not +t.**

### Symptom (Noise Cheap, CryptoHack LWE2)
With the wrong sign:
- BKZ on a 125×125 lattice "succeeds" (no errors, finishes in seconds)
- The candidate `e_0` looks plausible — entries in `{-1, 0, 1}` ✓
- But ~50% of subsequent verification samples fail (`b - A·S ∉ {-p, 0, p}`)
- The recovered `S` is GARBAGE (it satisfies the wrong relation)

The verification noise hovering near 50% is the dead giveaway: BKZ found
A short vector, just not THE short vector. The lattice is symmetric enough
under sign flip that wrong-sign embedding finds a different but legitimate
short vector that has nothing to do with our target.

### Other variants of the same bug
- Embedding `−y` instead of `+y` in the target row
- Embedding `+W^T` vs `−W^T` in the upper-right block (related but
  different — this changes the lattice itself, not just the target)

## 어떻게 해결했나 (B)

### Sign convention drill
Always derive from scratch:
1. State the relation as `<lattice element> ≡ <target> (mod q)` with the
   constraint that their **difference** is the small vector you want
2. Pick the lattice basis B so its elements look like
   `(e_0, W·e_0 + q·k)`. Verify: row j with `B[j,j] = 1` and
   `B[j, n+i] = W[i,j]` (POSITIVE) gives `(a, W·a)`
3. Decide your target as a *desired* point: `t = (0, -y)` because
   you want `W·e_0 ≈ -y` so that `e_0 + e_new` is the closest difference
4. Kannan: embed `−t` in the last row, NOT `+t`. So:
   `B[n+m, n+i] = +y[i]`, `B[n+m, n+m] = K`
5. The short vector in the BKZ output has the form `(e_0, e_new, ±K)`.
   Look for rows whose last entry is `±K` (NOT necessarily +K — sign of
   the whole row is arbitrary, so accept either)

### Verification before trusting
After extracting candidate `e_0`, **always verify against ALL collected
samples** before assuming success:

```python
S = A0_inv * (c0 - e0_vec)
bad = sum(1 for (A, b) in all_samples
          if (b - dot(A, S)) % q not in valid_noise_set)
if bad > 0:
    raise SystemExit(f"S verification failed: {bad}/{len(all_samples)} bad")
```

If `bad ≈ len(samples) // 2`, it's almost certainly a sign error in
the embedding (not a BKZ block-size issue, not a sample-count issue).

## 적용 범위
- **Any** LWE/Ring-LWE/HNP attack using primal lattice + Kannan embedding
- DSA/ECDSA biased-nonce HNP (Boneh-Venkatesan) — same trap with the
  `B[i] - q/2` centering vs the embed row
- BDD-style closest vector problems where you build a lattice and need
  to find a target close to a known point
- Any time you mix a "lattice basis" + "target row in same matrix": stop
  and re-derive the sign

## 출처
- CryptoHack: Noise Cheap (LWE2, 60pts)
  - n=64, p=257, q=1048583 prime, e ∈ {-1, 0, 1}
  - Build short-secret embedding, BKZ-20, Kannan target row
  - **wasted ~30 minutes** on the sign before realizing it was Kannan's
    `−t` convention, not a math error in W or y

## 메모
- The `(−t, K)` vs `(t, K)` ambiguity is *the* most common Kannan bug.
  fpylll/Sage docs are inconsistent on which they use as default
- Some implementations put `K` on top of the embed row (i.e., flip the
  block layout). Same trap — re-derive every time
- Sanity test: if BKZ finds `e_0` with the right *shape* (entries in the
  expected range) but `S` verification fails on >10% of samples, suspect
  sign before suspecting block size or sample count
- LLL alone is usually NOT enough for short-secret embeddings >80 dim;
  use BKZ with block_size 20-30
