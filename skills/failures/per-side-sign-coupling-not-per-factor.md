---
name: per-side-sign-coupling-not-per-factor
description: x-only PH ±k ambiguity is coupled per "y-lift unit" (per prime side / per group), NOT per factor. Iterating 2^(num_factors) signs while fixing the base wastes time AND silently misses valid configs.
type: feedback
---

# Sign ambiguity in x-only PH is per-y-lift, not per-factor

## What I did wrong (An Evil Twisted Mind, 2026-05)

When recovering k from x-only oracle output across multiple prime factors:
- Got residues `[(q1, r1), (q2, r2), ..., (qn, rn)]` from PH per factor.
- Knew "x-only ⇒ ±k" so each `r_i` is `k mod q_i` OR `(q_i - k) mod q_i`.
- Iterated 2^(n-1) sign combos, fixing the first `r_1`'s sign as the "global sign absorber."
- Found valid K matches but they DIDN'T include the true k. WHY?

**Cause**: per-factor sign flips aren't independent. They're constrained by which y was chosen when lifting the x-coordinate to the elliptic curve. Within ONE lift (one y choice), all PH residues for that subgroup share the SAME sign. The ± toggles per **lift**, not per **factor**.

For invalid-curve-on-composite-modulus (CRT decomposes to multiple primes):
- 1 sign bit per prime side (= 1 sign bit per y-lift on each E_t(F_pi))
- NOT 1 sign bit per small prime factor

For 2 prime sides → 4 valid configs total: (s1, s2) ∈ {(+1,+1), (+1,-1), (-1,+1), (-1,-1)}.

When I "fixed base sign" to absorb global ±, I baked in the choice for whatever side that base factor lived on. Toggling individual same-side factors then produces INVALID configs (none of the 4 valid ones unless I happened to start in one of the two with that side's sign). So my 2^(n-1) iter only covered HALF of the valid set.

## Why: the math

PH on subgroup of order `q` projects (lifted_point) into <P_q>:
- `Q_q = (N/q) * lifted_point`, then `discrete_log(Q_q, P_q, ord=q)`.
- If `lifted_point = +k * P_t`, all DLs return `k mod q_i`.
- If `lifted_point = -k * P_t` (other y), all DLs return `(q_i - k) mod q_i`.
- So per-side, all residues flip together.

Across sides (different lifts in different groups), the sign choices are **independent** — you have one y to pick on each curve.

## How to apply

When doing PH on x-only output that decomposes via CRT into multiple "groups" (e.g., E_t mod p1 × E_t mod p2):

1. **Identify the lift granularity**. A "side" = one cyclic group where you make ONE y-sign choice. Count how many sides you have. (Composite mod with k prime factors → at most k sides. Single prime + x-only → 1 side.)
2. **Enumerate exactly 2^(num sides) sign combinations** of (sign per side), NOT 2^(num factors).
3. Within each combo, apply that side's sign to ALL its factor residues uniformly before CRT.
4. Verify each candidate K (e.g., recompute the oracle output with K, compare).

This is faster (4 vs 256 for k=8 factors / 2 sides) AND correct.

## Why "fix base sign" pattern was wrong

The "fix base sign to absorb global ±" trick works when ALL residues live in ONE group (one lift = one ± to choose). With multiple groups (multiple lifts), each group has its own ±, and fixing one base only absorbs that group's sign — leaving the others UNFIXED but incorrectly toggled at the per-factor level.

Symptom: BJ verification finds a "match" K that has BJ(K, x0) ≡ R, but K mod order doesn't equal the true privkey. That's because there are MORE than 2 valid K's (one per per-side sign combo), and the iteration stumbles into one of the wrong ones first.

## Related
- `attack/invalid-curve-composite-modulus-twist-crt` — case study (An Evil Twisted Mind)
- `attack/xonly-ladder-quadratic-twist` — single-side version (sign disambiguation simpler: 2 candidates)
- `failures/invalid-curve-attack-alternative-b` — Checkpoint had 2^N CRT loop; that was correct because there only 1 side existed but each PER-FACTOR residue came from a DIFFERENT oracle query (different lift each time)
