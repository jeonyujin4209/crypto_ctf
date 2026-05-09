---
name: invalid-curve-composite-modulus-twist-crt
description: EC scalar mul mod composite N=p1*p2 (no on-curve check) → CRT decomposes to mod p1 and mod p2; submit x0 hitting twist on EACH prime, recover k mod (lcm of smooth twist orders), CRT to k full
type: attack
---

# Invalid curve attack on composite-modulus EC

## Trigger

Server source has `modulus` that's a *composite* integer (e.g. 384-bit), uses formulas like Brier-Joye / Montgomery / Weierstrass diff-add **mod modulus** without checking primality and without on-curve test. Server gives back x of (k * P_x0). Common giveaway: "modulus" is named generically, and `is_prime(modulus)` is False.

## Why it works

- EC arithmetic on Z/(p1·p2) is, by CRT, the product of EC arithmetic on F_p1 and F_p2 (as long as no inversion fails — only at the very end of x-only formulas, on the Z-coordinate).
- Pick any x0 ∈ Z/N. Reduce mod each prime: x_pi := x0 mod pi.
- On F_pi, x_pi corresponds to a point on E(F_pi) if x_pi³+a·x_pi+b is QR mod pi, else on E_t(F_pi) (quadratic twist).
- Twist orders on each prime have their own smooth structure; |E_t(F_pi)| = 2·pi + 2 − |E(F_pi)|.
- If we choose x0 so that on each prime side we land on a smooth (or partially-smooth) twist, the implicit point on Z/N has order = lcm(N1, N2) where Ni is the smooth divisor of |E_t(F_pi)|.
- One oracle query = (k * P).x mod N. Reducing mod each pi gives x of (k * P_t_i). PH on each side, CRT all residues → k mod (N1·N2).
- If N1·N2 > 2 · max(privkey), k recovers uniquely (modulo the sign ambiguities below).

## Recipe

1. **Factor modulus first**. Sage `factor(N)` may take ages for 384-bit RSA-style; query factordb (see `tools/factordb-lookup-first`). Factors usually known.
2. For each prime pi:
   - Compute |E(F_pi)|, |E_t(F_pi)| via Sage `EllipticCurve(GF(pi),[a,b]).order()`.
   - Factor twist order. Pick smooth subset Ni — product of small factors that's tractable for PH.
   - Find non-residue d_i, build E_t = `EllipticCurve(F_pi, [a*d_i², b*d_i³])`.
   - Random point on E_t, scale by `|E_t|/Ni` until order Ni.
   - x of that point = x_Et_i. Convert to x on E (the original curve) via `x_E_i = x_Et_i / d_i mod pi` (since E ↔ E_t isomorphism over F_pi² maps x_E → d_i·x_E_t, so inverse: x_E = x_E_t / d_i).
3. CRT: x0 ≡ x_E_i mod pi for each prime → x0 mod N.
4. Submit, get R.
5. PH on each side:
   - R_pi = R mod pi. Multiply by d_i to get x on E_t_i.
   - Lift to E_t_i (one of two y's; doesn't matter, sign noise).
   - For each q | Ni: project = (Ni/q) * lifted_point; DL against base = (Ni/q) * P_t_i → residue r_q.
6. CRT residues across both sides.
7. **4 valid sign combos** (per-side sign coupling, see `failures/per-side-sign-coupling-not-per-factor`): try {(+1,+1),(+1,-1),(-1,+1),(-1,-1)} for (s_p1, s_p2). Each gives a candidate K. Verify locally by recomputing scalar mul on Z/N with K vs the server's R; valid combos all match (the implicit point has 4 lifts in E(F_p1²) × E(F_p2²)).
8. For each valid K: compute K mod order, then min(K mod order, order − K mod order). At most 4 candidate privkey values. Submit each via `get_flag` (the server source typically allows multiple guesses).

## Why per-side-not-per-factor?

Within a single prime side, all PH residues for {q1, q2, ..., qm | Ni} use the SAME y-sign of the lifted point. Negating y flips them all together. So sign noise has 1 bit per prime side, 2 bits total — 4 combos, NOT 2^(num factors).

Initial misjudgment: tried 2^total_factors and absorbed "global sign" by fixing base sign. That MISSES half the valid configs because per-side flip can't be reproduced by toggling individual factor signs while base is fixed. Just enumerate the 4 per-side combos directly.

## Implementation hints

- `K mod order ≠ K`: ord_P (= lcm of twist smooth orders) and `order` (the prime modulus of the privkey ring) are unrelated 192-bit numbers. So you can't just "mod order" to drop excess bits. The 4-candidate sweep handles this.
- Verify locally before submitting: recompute server's scalar mul on Z/N with candidate K and check x matches. Skips wasted server queries.
- Sage scalar mul on Z/N (composite): the EC class wants a field. Just reuse the Brier-Joye dbl/diffadd Python loop directly with `% modulus`. Don't try `EllipticCurve(Zmod(N), …)`.
- Twist parameter d: pick smallest non-residue (`d=2` then increment).

## Challenges

- CryptoHack **An Evil Twisted Mind** (Parameter Choice 2, port 13418) — `crypto{tw0_twists_for_th3_price_of_0ne}`. modulus = p1·p2 (192-bit each); twist of E mod p1 has factors `1965293129 · 3945014767 · 6911909839 · big_prime` (~95 smooth bits); twist mod p2 has `17 · 1789 · 8984179 · 9381319 · 83816652113 · big_prime` (~98 smooth bits). One submit, 60 second cap, 4 candidates → 2nd guess wins.

## Related

- `failures/invalid-curve-attack-alternative-b` — prime-modulus version (Checkpoint)
- `attack/xonly-ladder-quadratic-twist` — single-prime x-only twist attack
- `failures/per-side-sign-coupling-not-per-factor` — sign ambiguity bookkeeping
- `tools/factordb-lookup-first` — when Sage factor stalls
- `tools/brier-joye-x-only-recognition` — recognizing the formula pattern in server source
