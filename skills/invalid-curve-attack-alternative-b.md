---
name: invalid-curve-attack-alternative-b
description: Invalid curve attack on ECDH where the server doesn't validate point-on-curve. Recover the secret by submitting points from OTHER curves (different `b`, same `p, a`) that have smooth order, then PH + CRT.
type: feedback
---

Classic invalid curve attack: an ECDH server does scalar multiplication `d * Q` without verifying that `Q` actually lies on the intended curve. Since short-Weierstrass addition formulas only use `p, a` (not `b`), the scalar mul computes in the group of whatever curve `Q` is on — namely `y² = x³ + a*x + b'` where `b' = y² - x³ - a*x` for the attacker's chosen `(x, y)`. Call this the "alternative curve".

**What I failed to realize on Checkpoint (CryptoHack EC Parameter Choice 2):** looking at the source, I saw it was using `double_and_add` without a check in `ecdh_kex`, noted the invalid curve vulnerability, and marked it as "complex" because implementing "the full invalid curve attack" seemed labor-intensive. I was right that it's invalid curve, and right that it's labor-intensive — but not intractable. The writeup structure is:

1. Scan a small range of alternative `b'` values (≤ 100 or so)
2. For each, build `E' = EllipticCurve(GF(p), [a, b'])`, compute `E'.order()`, factor it
3. Keep curves whose order has small-prime factors you can attack (say, each factor ≤ 2^20)
4. For each "good" `b'`, find a point on `E'` of a specific small-prime order `q` — multiply a generator of `E'` by `E'.order() / q`
5. Submit the point's `(x, y)` to the ECDH oracle; the server returns (via some side channel — often AES encryption using `SHA256(str(shared.x))[:16]`) a test message you can use to recover `d mod q` by trying each candidate
6. Collect residues `d mod q_i` across many `q_i` until their product exceeds the order of the real curve's generator (or more practically, exceeds `2^n_bits_of_d`)
7. CRT the residues → recover `d`

**Why it feels hard but isn't, in pieces:**
- "Finding smooth-order alternative curves" is a 10-second `factor()` loop over `b'`
- "Point of order `q` on alt curve" is `(E'.order() // q) * E'.random_point()` with a quick order check
- "AES-test-message oracle" is just try 0..q-1, derive key, try `unpad(decrypt(test_ct))`, accept the one that succeeds (valid PKCS7 padding or known plaintext prefix)
- CRT is one line

**Key architectural insight I missed:** for Checkpoint specifically, the attack DOESN'T rely on the standard "quadratic twist" variant (which only gives you one extra group). It scans many `b'` values to find *many* independent attack curves, each contributing a few bits via PH on a different small factor. You can get 256+ bits of `d` via, say, 16–20 alternative curves each contributing 16–17 bits.

**How to apply:**
- If you see an EC scalar mul that doesn't call `assert Q in E` or similar, it's an invalid curve oracle.
- If short-Weierstrass, scan `b'` values and factor orders. If Montgomery, use the twist directly (only one alternative group).
- Decide how many independent small-prime attacks you need to cover the secret's bit length; aim for total product > 2 × secret bound so CRT uniquely determines.
- Budget a batch oracle query per factor; each is cheap but implementation boilerplate is nontrivial — write the submit+decrypt+check loop once and reuse.

**Code skeleton:**
```python
p = NIST_P256_p
a = NIST_P256_a
# Find smooth-order alt curves
good = []
for bp in range(2, 200):
    try:
        Ep = EllipticCurve(GF(p), [a, bp])
    except ArithmeticError:
        continue
    fac = factor(Ep.order())
    for q, e in fac:
        if 2^10 < q^e < 2^20:  # tractable PH subgroup
            good.append((bp, q^e))
            break
# For each, pick point of order exactly q^e, submit to oracle, recover d mod q^e
# CRT after collecting enough.
```

The skill is recognizing that "invalid curve attack" looks intimidating but decomposes into the same plumbing as Pohlig-Hellman + oracle-based DL. Don't mentally flag it as "complex" without at least sketching the pieces.
