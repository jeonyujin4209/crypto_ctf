# Real Eisenstein

- **Category**: Brainteasers Part 2
- **Points**: 150

## Problem

The flag is encoded as h = sum(ord(c_i) * sqrt(p_i)) where p_i are distinct primes. The ciphertext ct = floor(h * 16^64) is given. Recover the flag characters.

## Approach

The flag has 23 characters (15 unknown). Let S_i = round(sqrt(p_i) * 16^64). The problem becomes:

```
ct = sum(ord(c_i) * S_i)  (approximately)
```

Subtract the contribution of known characters (from the "crypto{...}" wrapper). The remaining unknown characters are ASCII values near 79 (midpoint of printable range).

Build an LLL lattice: center the unknowns around 79, set up a basis where the short vector corresponds to the deviations of flag characters from 79. LLL finds the short vector, recovering all flag characters.

## Flag

```
crypto{r34l_t0_23D_m4p}
```
