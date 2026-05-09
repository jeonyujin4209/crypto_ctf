---
name: factordb-lookup-first
description: When sage `factor()` stalls on a CTF modulus (~300+ bits, RSA-style), query factordb.com BEFORE waiting. Most CTF moduli are pre-factored.
type: tool
---

# factordb lookup before sage factor

## When

- Modulus is composite, no obvious small factor (trial-divide & Pollard rho fail).
- Sage's `factor(N)` runs > 60 sec without progress.
- Number is in 200–600 bit range (factordb's sweet spot).

## Cost comparison (An Evil Twisted Mind, 2026-05)

- 384-bit composite, two 192-bit prime factors
- Sage `factor()`: still running at 13 minutes, no result, killed
- factordb HTTP API: **0.3 seconds**, returned `status: FF` (fully factored) with both primes

CTF challenges almost always use moduli that have been computed before. Even private CTFs leave traces (people upload to factordb during solve attempts).

## Recipe

```python
import urllib.request, json
def factordb(n):
    url = 'http://factordb.com/api?query=' + str(n)
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode())
    # status: 'FF' = fully factored, 'CF' = composite factored partially,
    #         'C' = composite (unknown), 'P' = prime
    if data['status'] in ('FF', 'CF', 'P'):
        return [(int(p), int(e)) for p, e in data['factors']]
    return None
```

Status codes worth knowing:
- `FF`: fully factored (you're done)
- `CF`: partially factored — useful for getting some small factors out
- `C`: known composite, not factored — fall back to ECM/QS yourself
- `P`: prime
- `U`: unknown / not in DB

## Variations

- For **batch lookups** (many CTF challenges in one session), cache results locally.
- factordb also has a *report* endpoint to submit factors back; courteous to do for novel CTF moduli once you've factored them.
- If `status: U` (unknown), submit the number first (`http://factordb.com/index.php?query=N&queue=1`); sometimes other CTF solvers' jobs progress it within minutes.

## When this is a trap

- factordb has nonzero failure modes: occasional `status: P` for borderline-prime numbers (verify with Miller-Rabin).
- Don't use factordb if the modulus contains *any* identifying CTF info. Submitting it tells the world you're working on the challenge. (Generally OK for past CTFs; for live CTFs, factor offline.)

## Related
- `tools/sage-dlp-fp-feasibility` — Sage's DLP perf surprises (similar "trust black box" lesson)
- `attack/invalid-curve-composite-modulus-twist-crt` — case where factorizing the modulus unlocks the whole attack
