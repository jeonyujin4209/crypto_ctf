---
name: stuck-checklist-5-questions
description: Five-question checklist to run WHENEVER a challenge is flagged as "complex / skip". Catches decompose-failure, built-in-missing, title-hint-missed, second-weakness-missed, and existing-implementation-missed.
type: feedback
---

After a post-mortem of 6 problems I wrongly labelled "too complex / skip" during a CryptoHack run (Micro Transmissions, Checkpoint, Dual Masters, Breaking SIDH, Meet me in the Claw, A True Genus), every single block came from one of five cognitive shortcuts. The fix is to run the five questions below EVERY time I'm about to mark a problem as skipped or deferred.

## The 5 questions

**Q0 (최우선). 지금 내 판단 근거가 실측인가, 계산/추론인가?**

막혀 있을 때 가장 먼저 확인. "이 알고리즘은 infeasible", "이 attack은 안 될 것 같다" 같은 판단이 **실제 실행**에서 나왔는지, 아니면 머릿속 복잡도 계산에서 나왔는지 구분. 후자면 → 도구 실제로 돌려서 검증 먼저. 상세: `tools/try-first-principle`.

**1. Decompose test — did I break the attack into 3-6 named pieces, in ≤5 minutes, before calling it complex?**

Failure mode: seeing a named attack ("invalid curve attack", "Castryck-Decru", "claw-finding") and collapsing the whole thing into one "too hard" label. The label is almost always wrong because named attacks have **publishable** structure → decomposable into small pieces.

Correct move: spend 3 minutes writing down the pipeline as bullet points. If every bullet is "find X then Y then CRT" type plumbing, it's just boilerplate. Example (Checkpoint): (a) scan b' values, (b) factor each order, (c) keep smooth ones, (d) per curve: find order-q point, submit to oracle, brute q candidates, (e) CRT. Five lines. Zero research required.

**2. Built-in test — did I run `dir(obj)` or read the library docs BEFORE rolling my own?**

Failure mode: trusting challenge-provided helper functions (`dual()` from Abelian SIDH source) as the canonical API, or building custom workarounds for operations that are one method call away in the library.

Correct move: when working with Sage (or any math library), before writing a helper, run `dir(obj)` on the object. `EllipticCurveIsogeny.dual()`, `EllipticCurve.automorphisms()`, `E.torsion_basis()`, `discrete_log(..., operation='+')` — all exist and handle edge cases (automorphisms, normalization) that hand-rolled versions miss. Time cost of the check: 30 seconds. Time cost of hand-rolling and debugging: hours.

**3. Title hint test — does the challenge NAME contain a technical term I should google?**

Failure mode: reading the title as just a pun or flavor text. CryptoHack titles are load-bearing — they often encode the attack name directly.

Correct move: for every unknown word in the title, run "<word> attack in <category>" through a search. Examples I missed:
- "Meet me in the **Claw**" → claw-finding attack (Oorschot-Wiener)
- "A True **Genus**" → genus theory distinguisher on CSIDH
- "An **Exceptional** Twisted Mind" → exceptional curve / Smart's attack
- "**Twin** Keys" → pun but also "twin" hinted at pair of primes
- "**Too Honest**" → prover leaks too much (z unreduced, e unbounded)

**4. Second-weakness test — did I check for a SECOND exploitable weakness after spotting the first?**

Failure mode: seeing one weakness (e.g. "64-bit secret") and mapping straight to the obvious attack (BSGS), missing that a second weakness (e.g. "smooth curve order") enables a much better attack.

Correct move: for EC challenges, always run `factor(E.order())` regardless of what else I noticed. For RSA, always check `e`, `d`, `n`'s structure (smooth p-1/q-1, small d, shared factor). For symmetric, check key derivation, nonce source, padding mode, MAC-then-encrypt vs encrypt-then-MAC. The first weakness I spot is rarely the only weakness, and often not the intended one. Spending 2 minutes enumerating weakness categories is cheap.

The specific Micro Transmissions bite: I saw `nbits = 64` and locked onto bounded BSGS (2^32 ops ≈ hours), completely failing to check the curve order. The order had seven small prime factors whose product exceeded 2^64 → Pohlig-Hellman solves in seconds. The 64-bit bound was actually a red herring / fallback; smooth order was the intended exploit.

**5. Existing-implementation test — did I search GitHub for the named attack BEFORE concluding I'd have to write it from scratch?**

Failure mode: assuming "paper attack = from scratch math implementation". Publishable attacks often come with public code, and the more famous the attack, the more likely there's a maintained Sage port.

Correct move: if the attack has a name (or the challenge description links a paper), run `github.com <attack name>` and `<attack name> sage implementation` searches. Five-minute budget. Examples:
- Castryck-Decru 2022 → github.com/jack4818/Castryck-Decru-SageMath
- Smart's anomalous attack → many Sage gists
- Manger's OAEP attack → reference implementations exist
- SIDH MITM claw-finding → dedicated repos with mitm.py

If an implementation exists, the work is "clone + parameter substitute" not "implement from math". That's a different time budget entirely.

## How to apply

When I notice myself about to type "*(skipped — too complex)*" into a README, I MUST:

1. Run questions 1–5 above
2. For each NO, spend the time budget (5 min for decompose, 30 sec for `dir`, 2 min for title search, 2 min for second-weakness enum, 5 min for github search)
3. Total cost of running the checklist: ~15 minutes per problem
4. Only if all five pass and I still can't see a path, mark it as legitimately deferred

Without this check, my "skipped" pile becomes a pile of problems I *could* have solved in under an hour each but convinced myself were hard. 6 problems × 1 hour each = 6 hours of avoidable deferral in a single session.

## Meta-lesson about the meta-lesson

The common theme behind all five failure modes: **I treat difficulty as a property of the problem instead of a function of the tools I checked for and the effort I budgeted**. The five questions are really one question: "have I spent 15 minutes investigating, or am I bailing out after 3 minutes and calling it hard?"
