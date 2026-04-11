---
name: sage-isogeny-dual-builtin
description: Sage's `EllipticCurveIsogeny` has a built-in `.dual()` method. Use it instead of reinventing the dual via `codomain().isogeny(K) * iso` which introduces Aut(E) ambiguity.
type: feedback
---

Sage isogenies are first-class objects with a `.dual()` method that returns the TRUE dual:

```python
phi_hat = E_A.isogeny(K, algorithm="factored")
phi_hat = phi_hat.codomain().isomorphism_to(E_0) * phi_hat   # optional: normalize codomain
phi = phi_hat.dual()   # ← built-in, returns the CORRECT dual
```

`.dual()` handles all the automorphism bookkeeping internally — the returned morphism is canonically the dual, not just "some isogeny with the right kernel".

**What I tried instead (Dual Masters, first attempt):** I copied the `dual()` helper from Abelian SIDH's source code:

```python
def dual(phi):
    l, e = factor(phi.degree())[0]
    E = phi.domain()
    P, Q = E.torsion_basis(l^e)
    K = phi(P)
    if K.order() != phi.degree():
        K = phi(Q)
    phi_hat = phi.codomain().isogeny(K, algorithm="factored")
    phi_hat = phi_hat.codomain().isomorphism_to(E) * phi_hat
    return phi_hat
```

This builds the dual via a NEW isogeny with kernel `phi(P_or_Q)`, then composes with `isomorphism_to(E)`. The second step is deterministic-but-arbitrary: Sage picks ONE iso from `codomain() → E`, out of `|Aut(E)|` possibilities. For `y^2 = x^3 + 1` (j=0), Aut has 6 elements, so my custom-dual lands in the wrong sigma-class 5/6 of the time, and the recovered point is `σ(phi(P))` instead of `phi(P)`.

I spent a lot of time enumerating 6 × 6 = 36 combinations trying to find the right (sigma_E_0, sigma_E_A) pair. The right answer was just:

```python
phi_hat = E_A.isogeny(phi_a_Q_b, algorithm="factored")
phi_hat = phi_hat.codomain().isomorphism_to(E) * phi_hat
phi_recovered = phi_hat.dual()    # ← Sage does this for you
```

**Why Sage's `.dual()` is exact where my manual version isn't:** internally Sage tracks the "normalization" used when constructing the isogeny (Velu coefficients, etc.) and inverts the exact formulas, so no Aut-level ambiguity is ever introduced. The custom helper from Abelian SIDH source ONLY works cleanly when its input is a morphism whose codomain already equals the target curve — which is unreliable to guarantee without understanding the internal normalization.

**How to apply:**
- Whenever you need the dual of an isogeny in Sage, check `dir(phi)` or just call `phi.dual()` first. Don't roll your own.
- If you only have the kernel (not the isogeny), build the isogeny first via `E.isogeny(K, algorithm="factored")`, compose with `codomain().isomorphism_to(target)` if you need the codomain normalized, then call `.dual()`.
- For j=0 or j=1728 curves (non-trivial Aut), self-rolled dual helpers are especially dangerous because the Aut group has ≥ 4 elements.
- Abelian SIDH's `dual()` function is a TEACHING TOOL showing how the dual works mathematically — it's not a drop-in replacement for Sage's built-in when you care about the exact sigma.

**Secondary tip from this debug:** when you're hunting an Aut-ambiguity bug, Sage's `E.automorphisms()` returns the full list. You can enumerate and multiply into your construction to check whether some sigma fixes the issue. But usually the cleaner fix is to avoid the ambiguity in the first place by using built-ins that track it internally.

**Result:** Dual Masters yields `n` via one `.dual()` call plus a ±sign-disambiguated DL — ~30 seconds total, vs. hours of aut-enumeration pain. Flag: `crypto{but_I_only_gave_one_point?!}`.
