# No Way Back Home

- **Category**: Brainteasers Part 1
- **Points**: 100

## Problem

A key exchange protocol where Alice and Bob exchange values vka, vkb, and a shared value vkakb. An AES-encrypted flag is given along with n, vka, vkb, vkakb.

## Approach

Recover the shared secret v from the exchanged values:

```
v = vka * vkb * inverse(vkakb, n) mod n
```

This works because:
- vka = v * k_A mod n
- vkb = v * k_B mod n
- vkakb = v * k_A * k_B mod n

So vka * vkb = v^2 * k_A * k_B, and dividing by vkakb = v * k_A * k_B gives v.

Then derive the AES key as sha256(v) and decrypt the ciphertext.

## Flag

```
crypto{1nv3rt1bl3_k3y_3xch4ng3_pr0t0c0l}
```
