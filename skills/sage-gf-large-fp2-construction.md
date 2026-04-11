---
name: sage-gf-large-fp2-construction
description: For large primes, `GF((p, 2), modulus=...)` can trigger a GAP "order must be at most 65536" error on operations like `.list()`. Use `GF(p^2, 'i', modulus=...)` instead.
type: feedback
---

Challenge sources often use this idiom to define F_{p^2}:

```python
F.<i> = GF((p, 2), modulus=[1, 0, 1])   # or modulus=x^2 + 1
```

For small p, everything works. For large p (e.g. the 432-bit prime in André Encoding), some downstream operations go through PARI + GAP and hit:

```
TypeError: order must be at most 65536
```

on operations like `list(elem)`, `list(map(int, P.x()))`, or `E(x, y)` where Sage implicitly calls `_SageObject__custom_name` / GAP.

**Fix:** construct the field with the `p^2` syntax instead of the tuple syntax:

```python
F.<i> = GF(p^2, modulus=[1, 0, 1])
```

These LOOK equivalent but route through different code paths in Sage's finite field factory. The `p^2` form uses the `pari_ffelt` backend without the GAP fallback, while `(p, 2)` can end up requesting a GAP-backed group constructor that refuses orders > 65536.

**How to spot this trap:**
- Challenge source copy-paste begins with `GF((p, 2), ...)` or `GF((p, 2), name="i", ...)`.
- You get a `TypeError: order must be at most 65536` when you first touch a point via `E(x, y)` or try to iterate/list-convert an F_p² element.
- The error trace mentions `_gap_init_` or `libgap`.

**How to apply:** in your solver, replace the field construction with `GF(p^2, 'i', modulus=...)`, then rebuild `E`, points, and any coerced elements from that new field. Everything else (isogeny, Weil pairing, lift_x) should just work.

**One more quirk to watch:** challenge sources sometimes write `modulus=x^2 + 1`, which requires `x` to be a previously-defined polynomial generator. If you copy that literally into your solver without defining `x`, you get a `NameError`. The safe rewrite is always the coefficient-list form: `modulus=[1, 0, 1]`.
