---
name: isogeny-degree-leak-via-weil-pairing
description: If a challenge hides a secret in the DEGREE of an isogeny and leaks phi(P), phi(Q) for known P, Q, the Weil pairing immediately leaks the degree via `e(phi(P), phi(Q)) = e(P, Q)^{deg(phi)}`.
type: feedback
---

The Weil pairing is compatible with isogenies in this sense:

```
e(phi(P), phi(Q)) = e(P, Q)^{deg(phi)}
```

where both sides live in μ_n ⊆ F_{q^k}^*, n = order of the pairing, φ is any isogeny between two elliptic curves over the same base field.

**Implication for CTF:** if a challenge encodes a secret value `s` as `deg(phi) = f(s)` (with `f` a known function like `2^64 * s`) and sends us `phi(P), phi(Q)` for a known torsion basis `(P, Q)` of E₀, we can recover `s` from a single pairing computation — no isogeny reversal, no lattice, no MITM.

**Concrete recipe (André Encoding):**
1. Compute `α = e(P, Q)` on E₀ with pairing order `N = p + 1` (full torsion).
2. For each ciphertext entry, reconstruct the **codomain curve** from two image points: given `phi(P) = (x1, y1)` and `phi(Q) = (x2, y2)`, solve `y^2 = x^3 + a*x + b` by
   ```
   a = (y1^2 - y2^2 - x1^3 + x2^3) / (x1 - x2)
   b = y1^2 - x1^3 - a*x1
   ```
   then `E_new = EllipticCurve(F, [a, b])`.
3. Build `phi_P, phi_Q` on `E_new` and compute `β = phi_P.weil_pairing(phi_Q, N)`.
4. `β = α^{deg(phi)}`. If the range of possible degrees is small (e.g. `deg ∈ {2^64 * b : 0 ≤ b < 256}`), precompute a table of `α^{2^64 * b}` and do a hash lookup.

**Why it works:** the Weil pairing output lives in F_{p^2}^* regardless of which curve in the isogeny class you compute on, so values from different codomains are directly comparable.

**When to reach for this:**
- The challenge gives you `phi(P), phi(Q)` (possibly across multiple encryptions).
- A secret value controls degree or order of the isogeny.
- You see "SIDH-like" setup but the secret controls `deg(phi)` rather than a walk.

**When NOT to use this:**
- Only one image point is given (need two to reconstruct codomain curve OR to compute the pairing).
- The kernel generator is `P + n*Q` rather than n itself (this is "What's My Kernel" — there you use DL on `phi(P) = -n * phi(Q)` instead).
