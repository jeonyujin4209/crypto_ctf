---
name: sage-preparser-xor-trap
description: Sage preparser translates `^` to `**` (exponentiation), not bitwise XOR. Use `^^` or `int.__xor__` in Sage scripts.
type: feedback
---

In pure Python, `a ^ b` is bitwise XOR. **In Sage's preparsed `.sage` files, `^` is translated to `**` (exponentiation).** Sage uses `^^` for XOR.

This silently corrupts any Python code ported into Sage that uses `^`. The code still runs — it just computes the wrong thing.

**Why:** I spent a long session debugging A Twisted Mind (EC X-only ladder over F_p) because `scalarmult_E_x(2, x)` returned the wrong answer. Unit-tested the double formula directly — correct. Unit-tested the ladder — mismatch. I added prints inside the loop and saw that at the start of the loop, `R0` was not `(x0, 1)` as expected but had already been swapped to the R1 value. Tracing backwards, the culprit was:

```python
pbit = 0
for i in range(n-2, -1, -1):
    bit = (k >> i) & 1
    pbit = pbit ^ bit     # intended XOR
    if pbit:
        R0, R1 = R1, R0   # swap fires on first iteration!
    R1 = diffadd(R0, R1, x0)
    R0 = dbl(R0)
    pbit = bit
```

For `k=2`, the first (and only) loop iteration has `bit = 0`, so `pbit ^ bit = 0 ^ 0`. In Python that is 0; in Sage `0 ^ 0 = 0**0 = 1`. The `if pbit:` branch fires, R0/R1 get swapped, and the ladder computes the wrong multiple.

**How to apply:** When porting x-only ladders (or ANY Python code with `^`) into a `.sage` file:

- Replace every bitwise `^` with `^^`, OR
- Force the Python interpretation with `int(a).__xor__(int(b))`, OR
- Keep the ladder in a pure `.py` helper and import it from Sage

Quickest sanity check after any Python-to-Sage port: pick a non-trivial scalar (e.g. `k=2`) and verify the ladder matches `int((k * P).x)` from Sage's built-in EC. If k=1 passes but k=2 fails, suspect this trap first — operator preparsing quirks usually show up on the smallest non-identity input.

Other Sage preparser traps to keep in mind (less likely to bite but still tricky):
- Integer literals become `Integer(...)`, not Python `int`. Pass to `socket.create_connection((host, int(port)))` or similar APIs that require plain `int`.
- `^^` is Sage XOR; `^` is power. Opposite of Python.
- `a/b` between `Integer` may give a `Rational`, not integer division. Use `//` for floor division.
