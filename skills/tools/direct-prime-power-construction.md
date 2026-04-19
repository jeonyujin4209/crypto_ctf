---
name: direct-prime-power-construction
description: N = p^k 형태 필요하면 "smooth prime 검색"으로 시간 낭비 말고 직접 p prime 골라 p^k 쓸 것
type: skill
---

# Direct Prime Power Construction

## 패턴
문제 setup에서 "N = p^k 꼴"이 필요한 경우:
- CRT로 DLP/factor 분해 타겟
- Paillier-style p-adic lifting 필요
- 특정 group order 강제

AI가 흔히 빠지는 함정: **smooth composite N 찾기** 시도
- `N = 소수들 곱` 중 특정 조건 만족하는 것 탐색
- 시간 폭발, 확률 낮음

## 올바른 접근
**그냥 p를 prime으로 뽑고 p^k 계산**:
```python
from Crypto.Util.number import getPrime
p = getPrime(128)   # 128-bit prime
N = p ** 2           # 256-bit, p^2 구조 guaranteed
# 또는 p^3, p^4 등 필요에 따라
```

## 왜 이게 나은가
- Smooth search: 랜덤 N 중 "p-1이 smooth" 류 조건 만족할 확률 낮음
- Direct: O(1), 즉시 원하는 구조 획득
- `Crypto.Util.number.getPrime`, `sympy.randprime` 다 빠름

## 언제 쓰나
- 문제 생성 측 코드 (source.py) 이해할 때: `n = p**2` 봤다면 "smooth N 탐색으로 만든 게 아님"
- 로컬 재현(reproduction) 스크립트 짤 때: smooth search 쓰지 말고 직접 prime power
- Simulated challenge environment 구성 시

## 관련 패턴
| 용도 | 구조 |
|---|---|
| Paillier-like p-adic log | N = p^2 |
| Gaussian integer DH | n = p^2 (p ≡ 3 mod 4) |
| CRT 분해 타겟 | N = p*q (두 prime) |
| Smooth group order | `p = 2 * small_primes_product + 1` 류 탐색 필요 |

## 관련 스킬
- `attack/gaussian-int-padic-dlp` — n = p^2, p ≡ 3 mod 4
- `failures/sympy-discrete-log-pk-oom` — p^k DLP는 Hensel lifting
