---
name: pss-r-schnorr-redundancy-as-haystack-filter
description: Schnorr/ECDSA-style signature with message-recovery (PSS-R) padding `m1 = F1(m) || (F2(F1(m)) XOR m)`. The OAEP-style redundancy is a built-in verifier-side oracle — use it to filter "real signature among N random ones" challenges in O(N) verifications.
type: attack
---

## Pattern

Some signature schemes embed the message in the signature itself (message recovery, PSS-R, ISO/IEC 9796) instead of hashing it. The padded message uses an OAEP-like structure:

```
m1 = F1(m) || (F2(F1(m)) XOR m)        # |F1(m)| = k1, |m| = k2
r  = (ω * G).x_bytes XOR m1
c  = H(r)
z  = ω + c * x   (mod p)
```

Verifier:
1. `R = z*G + c*Y` (if `Y = -x*G`) or `R = z*G - c*Y` (if `Y = x*G`) — recovers `ω*G`.
2. `m1 = r XOR R.x_bytes`
3. Split `m1 = a || b`, compute `m = F2(a) XOR b`, **check `F1(m) == a`** ← the redundancy.

The redundancy check has security parameter `k1` bits (typically 256–320). Random forgeries fail with prob `2^-k1` per attempt, so the verifier is itself a strong filter.

## Attack: needle-in-a-haystack

If a CTF gives you `N` candidate sigs and tells you only one is real (the rest are `(random_bytes, random_int)`), you don't need to break the scheme — just **run the verifier on each candidate**. Random `(r, z)` produces random `R`, random `m1`, random `(a, m)`, and `F1(m) == a` fails with overwhelming probability.

```python
for r_hex, z in sigs:
    r = bytes.fromhex(r_hex)
    c = int.from_bytes(H(r), "big")
    R = z * G + c * Y                       # sign convention!
    if R == 0: continue
    m1 = xor(int(R.xy()[0]).to_bytes(rbytes, "big"), r)
    a, b = m1[:k1//8], m1[k1//8:]
    m = xor(F2(a), b)
    if F1(m) == a:
        return m   # the real message
```

Cost: `N * 2` scalar mults. On Ed448 in Sage: ~24s for N=10000 (well within reach).

## Sign-convention gotchas

- `Y = -x*G` → verify uses `R = z*G + c*Y`. 흔히 안 쓰는 convention. 코드에서 `Y = -x*G` 보면 즉시 부호 뒤집기.
- TwistedEdwards 표기여도 sage에선 birational Weierstrass로 변환하고 점/스칼라 연산. `to_weierstrass`/`to_twistededwards` 헬퍼 보존.
- `(ω*G)[0]` 또는 `(ω*G).xy()[0]` — Weierstrass X 좌표를 그대로 바이트화. Edwards-y가 아님 주의.

## When to recognize this

키워드 — `m1 = F1(m) || (F2(F1(m)) XOR m)`, `m = F2(a) XOR b`, `r = (ω*G)[0] XOR ...` 같은 스니펫이 보이면 **PSS-R / Abe-Okamoto-style** 시그니처. 챌린지 화면에 N개 시그니처 중 1개만 진짜라고 명시되면 곧바로 verifier-as-filter 공격.

## Why it's not "an attack" but feels like one

PSS-R는 verifier가 redundancy를 체크해서 위조가 어렵게 설계된 것. CTF 출제자는 "noise sigs 중 진짜 1개 찾기" 게임을 만들었지만, 실제로는 **모든 PSS-R verifier가 자동으로 필터** — 서명 위조가 아니라 단순 verify 호출.

일반화: signature scheme이 redundancy/integrity check를 내장하면 그 check를 노이즈 필터로 재활용. EMV CDA, ISO 9796-2, RSA-PSS-R 등 동일 구조.

## 출처

ECSC 2023 Norway "Blind" — Ed448 PSS-R Schnorr (`Y = -x*G` 부호 주의), 10000 sigs 중 진짜 1개 찾기. F1 출력 320비트라 무작위 통과 확률 `2^-320` ≈ 0. 24초만에 idx=7135에서 진짜 발견 → bcrypt KDF로 AES 키 유도 → AES-CTR 복호화.
