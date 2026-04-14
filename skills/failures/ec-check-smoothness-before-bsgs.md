---
name: ec-check-smoothness-before-bsgs
description: Before reaching for BSGS on a "small secret" ECDLP, always `factor(E.order())`. If the order is smooth, Pohlig-Hellman is orders of magnitude faster and Sage handles it automatically.
type: feedback
---

When you see an ECDLP challenge with a stated "small private key" (e.g. `nbits = 64`) on a 256-bit curve, the obvious move is bounded BSGS — `bsgs(G, A, (0, 2^64))` takes sqrt(2^64) = 2^32 ≈ 4 billion group ops, minutes to hours, and often times out.

**What I missed on Micro Transmissions:** I wrote a BSGS solver and a pure-Python fallback, estimated "~1.5 hours with gmpy2", flagged it as "SageMath 필요: BSGS" and skipped it. What I SHOULD have done first is:

```python
factor(E.order())
```

For that specific curve, the order is `7 * 11 * 17 * 191 * 317 * 331 * 5221385621 * ...` — extremely smooth. The first seven factors multiply to > 2^64, which uniquely determines any 64-bit secret. Pohlig-Hellman over those tiny subgroups takes **seconds**, not hours. Sage's `discrete_log` auto-uses PH when you give it the full curve order:

```python
n_a = discrete_log(A, G, ord=G.order(), operation='+')
```

(no `bounds=` argument — bounds forces a bounded BSGS mode that is *slower* here, not faster.)

**Rule of thumb:** before committing any implementation time on an EC secret-recovery challenge, do this sanity check FIRST (it's 2 lines of Sage):

```python
E = EllipticCurve(GF(p), [a, b])
print(factor(E.order()))
# If the order is smooth up to ~2^30 for the biggest factor and the
# product of small factors >> (bound on secret), Pohlig-Hellman wins.
```

If the order is smooth enough, you're done in seconds. If it isn't, only THEN consider bounded BSGS / baby-giant tricks on the "small secret" bound.

**The broader pattern:** "small secret" and "smooth order" are two INDEPENDENT weaknesses. The challenge setter may have introduced BOTH, and either is sufficient to break the scheme. Check the cheaper one (smoothness) before committing to the more expensive one (BSGS over the secret's range). In my experience, the smooth-order attack is almost always the intended solution — CTF challenge authors rarely ship a 64-bit secret on a prime-order curve of that size because it's computationally wasteful (for them to generate) and unnatural.

One more footgun from this debug session: Sage's `EllipticCurvePoint_finite_field` objects do NOT have a `.discrete_log(target)` method. Use the global `discrete_log(target, base, ord=..., operation='+')` function. The method form only exists for abstract `AdditiveAbelianGroup` elements.
