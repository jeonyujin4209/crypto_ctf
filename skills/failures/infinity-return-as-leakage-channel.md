---
name: infinity-return-as-leakage-channel
description: Server source returning a sentinel like "Infinity" / "error" on EC scalar-mul corner cases (Z=0, GCD(Z, modulus)≠1) is a deliberate-or-accidental leakage channel — confirms `(k·P) ≡ O` in some quotient group. If ord(P_F) is smooth there, it leaks `k mod ord(P_F)`. Don't dismiss the branch as harmless safety code.
type: feedback
---

# "Infinity" / safety-sentinel returns are a side channel

## What the pattern looks like

```python
def scalarmult(scalar, x0):
    ...
    if GCD(R0[1], modulus) != 1:
        return "Infinity"
    return R0[0] * inverse(R0[1], modulus) % modulus
```

or:

```python
try:
    return (scalar * P).x()
except ZeroDivisionError:
    return None
```

The author *added* this branch to avoid a crash. But the branch's existence is **observable from the client**: a string vs an integer. That's information.

## What it leaks

When BJ x-only / Montgomery ladder mod composite N produces final Z that's not coprime to N, it means `(k · P)` reduces to the identity O modulo some prime factor of N (or the prime if N = p^k). Concretely:

- **N = p · q (composite)**: Z ≡ 0 mod p ⇒ k · P_F = O in E(F_p) ⇒ `k ≡ 0 (mod ord(P_F))`. Same for q. The "Infinity" return tells you k vanishes in *at least one* of the two reductions.
- **N = p^k (prime power)**: Z ≡ 0 mod p ⇒ result is in formal-group kernel ⇒ same conclusion `k ≡ 0 (mod ord(P_F))`.

If you can pick a base point P with `ord(P_F) = m` for some controllable `m` (smooth or otherwise), one bit of "Infinity vs not" tells you `k mod m == 0`. With multiple queries, this generalizes to a *Pohlig-Hellman per oracle branch*.

## When this matters in practice (and when it doesn't)

For **An Exceptional Twisted Mind** (CryptoHack), `|E(F_p)| = order` is a 256-bit prime. The only way to get "Infinity" is k ≡ 0 mod that prime, i.e., k = 0 — useless leak. So the safety branch was *defensively useless* (didn't open a real channel). But this is the exception:

- If `|E(F_p)|` had any small prime factor q, picking a base point of order q would let one query reveal k mod q for free.
- For the composite-modulus version (Z/p_1·p_2), you can construct P with ord(P_F) tailored to either side.

So **don't write off** "Infinity" / safety branches in the source. Always trace:
1. What does the server return on this branch?
2. What server-side condition causes the branch?
3. If condition = `result ≡ O in some group G`, then I can learn `k ≡ 0 (mod ord_G(P))` per query.
4. Can I choose P so that `ord_G(P)` is small / structured?

If yes ⇒ it's a real attack channel.

## Why I would have missed it

When skimming server source, "looks like a safety check" pattern matches benign defense. Mental flag: *"defensive code = fine, move on."* But CTF authors sometimes leave these in, knowing solvers might exploit them, and sometimes they're vestigial / accidental.

## How to apply

When reading EC / DLP server source:
- Note **every branch** that returns a different shape (string vs int, error vs success, fixed sentinel).
- For each branch, write down the condition that triggered it. If the condition is `point at infinity`, `Z divisible by ...`, `inverse failed`, `result == 0`, that's a candidate side channel.
- Then check: can I find a base point whose `ord(P) mod (relevant subgroup)` is something I want? If yes, multi-query oracle.
- Even if **|E(F_p)| is prime** (so direct "k mod prime" leak is useless), check the **twist** order — if pickable. Or composite-prime CRT case.

## Related
- `attack/smart-lift-attack-Zpk-modulus` — the case where "Infinity" was a defensive shrug, not a leak (because |E(F_p)| was prime)
- `attack/invalid-curve-composite-modulus-twist-crt` — composite case where smooth twist orders DO let "Infinity" become a leak
- `failures/invalid-curve-attack-alternative-b` — `q=2` and `d≡0 mod q` server-crash gotchas, related theme of error-channel leakage
