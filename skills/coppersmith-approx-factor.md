---
name: coppersmith-approx-factor
description: 소인수 p의 근사값만 알 때 Coppersmith small_roots로 정확한 p를 복구하는 패턴 (예: sqrt(p) 기반 hint에서 오류 ~2^585인 경우)
type: skill
---

## 상황

`hint = floor(D * sqrt(p) + D * sqrt(q))` 형태의 힌트가 주어지는 경우.

- `hint / D ≈ sqrt(p) + sqrt(q)` with error < `1/D`
- 이차방정식의 두 근으로 `sqrt(p)`, `sqrt(q)` 근사 → `p_approx = round(sqrt(p)^2)`
- **p_approx의 오류 = `2 * sqrt(p) / D`**
  - D ≈ 2^84이면 오류 ≈ 2^(669-84) = **2^585**
- 아무리 고정밀도 부동소수점을 써도 `floor()`가 ~85비트 정보를 파괴하므로 p 정확 복구 불가

## 왜 naive 접근이 실패하나

```python
# 이렇게 하면 delta를 ±100 범위에서 탐색해도 절대 못 찾음
for delta in range(-100, 101):
    if n % (p_approx + delta) == 0: ...
# 실제 오류가 2^585 ≈ 10^176 이므로 ±100은 의미없음
```

## 올바른 접근: Coppersmith

`f(x) = p_approx + x`의 작은 근(small root)을 찾으면 됨.

- 조건: `|x| < X = 2^600`
- Coppersmith 성립 조건: `X < N^{1/4} ≈ 2^668` ← 만족

```sage
# SageMath (solve.sage)
from sage.all import *
from mpmath import mp, sqrt as mpsqrt, nint as mpnint

# 1. 고정밀 근사 (fp 오류는 무시가능, 지배 오류는 floor()에서 옴)
mp.dps = 2000
s = mp.mpf(hint) / mp.mpf(D)    # ≈ sqrt(p) + sqrt(q)
t = mpsqrt(mp.mpf(n))
disc = s*s - 4*t
u = (s + mpsqrt(disc)) / 2      # ≈ sqrt(p)
p_approx = int(mpnint(u * u))

# 2. Coppersmith
X_bound = ZZ(2)^600
PR.<x> = PolynomialRing(ZZ)
f = ZZ(p_approx) + x
roots = f.change_ring(Integers(ZZ(n))).small_roots(X=X_bound, beta=0.5, epsilon=0.02)

for r in roots:
    p_cand = ZZ(p_approx) + ZZ(r)
    if ZZ(n) % p_cand == 0:
        p, q = int(p_cand), int(ZZ(n) // p_cand)
        break
```

## 오류 크기 계산법

| D 비트 수 | sqrt(p) 비트 수 | p_approx 오류 | N^{1/4} | 성립? |
|-----------|----------------|--------------|---------|-------|
| 84 | 669 | 2^585 | 2^668 | ✅ |
| 50 | 512 | 2^462 | 2^512 | ✅ |
| 300 | 512 | 2^212 | 2^512 | ✅ |

일반적으로 `2 * sqrt(p) / D < N^{1/4}` ↔ `D > 2^{3*bitlen(p)/4}` 이면 성립.

## Docker에서 SageMath 실행 (Windows Git Bash)

```bash
# sage 직접 경로 지정이 안 될 때 PowerShell 사용
powershell -Command "docker run --rm -v 'D:/path/to/ctf:/work' sagemath/sagemath:latest bash -c 'sage-preparse /work/solve.sage && python3 /work/solve.sage.py'"
```

## 관련 챌린지

- 1337crypt (DownUnderCTF 2020): `D = 63^14 ≈ 2^84`, p,q 1337비트
