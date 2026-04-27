---
name: rabin-reciprocal-irreducible-discriminant-leak
description: |
  Williams' Rabin-with-reciprocal (M3) implementations that "solve" x^2-rx+c mod p
  via res_poly = x^((p-1)/2) mod (x^2-rx+c) bug out when the discriminant r^2-4c
  is QNR mod p — the polynomial is then IRREDUCIBLE (over GF(p^2)) and the
  formula a1 = -(res[0]-1)/res[1] returns a bogus a1 with a1+a2=r mod p but
  a1*a2 ≠ c mod p. CRT-gluing this bogus root with the valid mod-q root yields
  a "decryption" m' whose re-encrypt r' agrees with r mod q but not mod p.
type: attack
---

# Rabin-with-reciprocal: irreducible-quadratic decryption oracle

## Setup

- Server keeps n=pq (both p,q ≡ 3 mod 4), random c with jacobi(c,p)=jacobi(c,q)=-1.
- Encrypt: `r = m + c·m^{-1} mod n`, plus `s = jacobi(m,n)`, `t = (c·m^{-1} < m)`.
- Decrypt solves `x^2 - r·x + c = 0` mod p and mod q via `solve_quad`, then CRT
  + filter by `s` + select by `t`.
- `solve_quad(r, c, p)` computes `x^((p-1)/2) mod (x^2 - r·x + c)` in `GF(p)[x]`
  and reads off roots from `res_poly[0]`, `res_poly[1]`.

## The bug

When `disc = r^2 - 4c` is a QNR mod p, the quadratic is irreducible — there
is no actual root in GF(p). The polynomial-exponentiation still produces a
res_poly, and the formula `a1 = -(res[0]-1)*res[1]^{-1}` computes a bogus
`a1 ∈ GF(p)`. Always `a1 + a2 = r mod p`, but `a1·a2 ≠ c mod p`.

Server happily CRTs `(bogus_a_p, valid_root_q)` and re-encrypts.

## Oracle: `encrypt(decrypt(·))` returns `r_new`

When the bug fires only mod p (and mod q is fine):
- `r_new mod q = r mod q` (good side)
- `r_new mod p ≠ r mod p` (bug side, depends on bogus a)

So `q | (r_new - r)` and `p ∤ (r_new - r)` typically. Symmetric for bug-mod-q.

## Attack steps

### 1. Factor n by gcd

Send ~60-80 random `(r, s, t)` queries with `r < 2^(2·pbits-5)` (so `r < n`).
Collect non-zero diffs `d_i = r_new_i - r_i`. Pairwise `gcd(d_i, d_j)`: ones
that come out at exactly `pbits` size are p or q (with high probability).
Filter `is_prime` to deduplicate composites.

### 2. Recover c mod p (and mod q)

Find a query whose diff is divisible by q but not p (i.e., bug only mod p).
Replay with **the same `r_in`** under all 4 `(s, t) ∈ {±1}×{0,1}` combinations.
The decrypt's filter picks different bogus-a (a1 vs a2) across these, so we
collect distinct `r_new mod p` values.

Each gives `r_new ≡ a + c·a^{-1} mod p` with the constraint `a1 + a2 = r_in`.
Two distinct values `rn1, rn2` from {a1, a2} give a 1-unknown system:

```
a1 = r_in · (rn2 - r_in) / (rn1 + rn2 - 2·r_in)   mod p
c  = rn1 · a1 - a1^2                              mod p
```

Verify with: `(r_in - a1) + c·(r_in - a1)^{-1} ≡ rn2 mod p`. Same trick mod q,
then CRT to `c mod n`.

### 3. Decrypt the flag

With `p, q, c` known, decrypt `enc_flag = (r0, s0, t0)` correctly using
Tonelli-Shanks (since `p,q ≡ 3 mod 4`, `sqrt(x) = x^{(p+1)/4} mod p`):

```python
disc = r0^2 - 4c mod p; sd = pow(disc, (p+1)//4, p)
mp1, mp2 = ((r0+sd)/2, (r0-sd)/2) mod p   # same mod q
# 4 CRTs, filter jacobi==s0, pick max if t0==1 else min
```

## Verified

HackTM 2023 "broken oracle". Total ~85 queries to flag in ~30s.
See `cryptohack/CTF Archive/2023/broken oracle (HackTM CTF)/solve.py`.

## Don't confuse

- `r=0` query reveals nothing: r_new always 0 (since c·m^{-1} = -m for m^2=-c).
- Sending `s=-s0` does NOT give `n - r0`: those candidates {m', m''} satisfy
  `m'·m'' = c mod n`, so encrypt(m') still returns r0.
- Both p and q-mod bug at once gives "noise" diff (random); filter by size.
