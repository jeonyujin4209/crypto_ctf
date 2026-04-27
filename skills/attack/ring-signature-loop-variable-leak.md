---
name: ring-signature-loop-variable-leak
description: Python `for` loop variable leaks past loop end. CryptoNote/MLSAG-style ring signature reuses the same name `q` for both signer-nonce and decoy-nonce inside the loop; after the loop, `q` retains the value from the LAST iteration. If the signer is at any index < last, the final closing equation `sigr[my_index] = q − sigc[my_index]·sk` uses the decoy-q from i=last instead of the signer's own q. That decoy-q equals the publicly written `sigr[last]`, so attacker has a linear equation in sk and can de-anonymise (and recover sk).
type: attack
---

# Ring signature: Python loop variable scope leak (CryptoNote/MLSAG)

## Trigger
Spotted in ECSC 2023 "Put a ring on it" (Monero `mininero` ed25519 ring sig).
Generic pattern — applies to any ring/group signature where:
1. Loop iterates over ring positions, generating fresh nonces each iter.
2. Signer branch and decoy branch reuse the SAME variable name (here `q`).
3. The final closing line outside the loop references that variable name.

## Vulnerable code shape
```python
for i in range(RING_SIZE):
    if i == my_index:
        q = random_scalar()        # signer's nonce
        L = pk(q); R = ...
    else:
        q = random_scalar()        # DECOY q — overwrites signer's q
        w = random_scalar()
        L, R = decoy(q, w, ...)
        sigc[i] = w
        sigr[i] = q                # decoy-q published
    buf += L + R
c = H(buf)
sigc[my_index] = (c - sumc) % l
sigr[my_index] = (q - sigc[my_index] * sk) % l   # <-- BUG: q from last iter
```

## Leak math
After the loop, Python keeps `q = q_{RING_SIZE-1}`.

- If `my_index == RING_SIZE-1`: q is signer's own nonce — sig is valid as designed.
- If `my_index < RING_SIZE-1`: q is the decoy-q at i=last, which equals `sigr[last]` (published).
  Hence:
  ```
  sigr[my_index] ≡ sigr[last] − sigc[my_index]·sk   (mod l)
  =>  sk ≡ (sigr[last] − sigr[my_index]) · sigc[my_index]^{-1}   (mod l)
  ```

## De-anonymisation recipe
For each candidate `cand` in `0 .. RING_SIZE-2`:
```python
sk_guess = (sigr[-1] - sigr[cand]) * pow(sigc[cand], -1, l) % l
if scalarmult_base(sk_guess) == public_keys[cand]:
    my_index = cand
    break
else:
    my_index = RING_SIZE - 1   # no match -> signer was at the last position
```
Cost: at most `RING_SIZE-1` scalar multiplications per ring.

## Why this works (ed25519 quirk)
`random_scalar()` returns 256-bit value; `l ≈ 2^252`. So recovered `sk_guess` is sk mod l — different integer than original draw, but same point. Match on the public key, not the integer.

## Generalisation
Same bug shape in MLSAG, bLSAG, Schnorr-OR, any "balanced" closed-loop sig where decoy-and-signer branches share variable names. Always grep for variables assigned in both branches of the inner if/else and used after the loop.

## Counter-attack pattern (defender)
Use distinct names: `q_signer` vs `q_decoy` (or pop `q` from scope after loop).
