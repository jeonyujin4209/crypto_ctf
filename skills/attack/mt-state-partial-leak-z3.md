---
name: mt-state-partial-leak-z3
description: random.random() 53-bit 관측 → Z3로 MT19937 state 복원. 624 floats (정확히 2 twist cycle) = unique solution. getnext() 큐 모델이 핵심.
type: skill
---

## 상황

`random.random()`의 출력을 연속으로 관측 가능한 시나리오.

```c
// CPython 내부
a = genrand_uint32() >> 5   // 27 bits
b = genrand_uint32() >> 6   // 26 bits
return (a * 2^26 + b) / 2^53
```

→ float 1개당 27+26 = **53비트** leak, 11비트 hidden.

## 핵심: 624 floats만 있으면 충분

- 624 floats = 1248 getnext() 호출 = **정확히 2 twist cycle**
- 1248 × 27/26 bits ≫ 624 × 32 bits state → over-determined → unique solution
- **N=312 (1 twist cycle):** 53×312 = 16536 < 19968 bits → **under-determined, 반드시 실패**
- **N=624 (2 twist cycles):** 33072 > 19968 → unique ✓

## getnext() 큐 모델 (권장, 빠름)

```python
from z3 import *
import random

def mtcrack_floats(arr):
    """624개의 연속 random.random() 출력으로 MT state 복원.
    반환: 관측 직후 위치에 동기화된 Random 객체."""
    MT = [BitVec(f'm{i}', 32) for i in range(624)]
    s = Solver()

    def cache(x):  # 중간값 캐시 → Z3 속도 향상
        tmp = Const(f'c{len(s.assertions())}', x.sort())
        s.add(tmp == x)
        return tmp

    def tamper(y):
        y ^= LShR(y, 11)
        y = cache(y ^ (y << 7) & 0x9D2C5680)
        y ^= cache((y << 15) & 0xEFC60000)
        return y ^ LShR(y, 18)

    def getnext():
        # CPython in-place twist를 큐로 모델링
        x = Concat(Extract(31, 31, MT[0]), Extract(30, 0, MT[1]))
        y = If(x & 1 == 0, BitVecVal(0, 32), BitVecVal(0x9908B0DF, 32))
        MT.append(MT[397] ^ LShR(x, 1) ^ y)
        return tamper(MT.pop(0))

    def getrandbits(n):
        return Extract(31, 32 - n, getnext())

    # 624 floats × 2 getnext() calls = 1248 calls = 2 full twists
    s.add([Concat(getrandbits(27), getrandbits(26)) == int(f * (1 << 53))
           for f in arr])

    assert s.check() == sat
    state = [s.model().eval(x).as_long() for x in MT]

    r = random.Random()
    r.setstate((3, tuple(state + [0]), None))  # index=0: 관측 직후 상태
    return r
```

`setstate(..., [0])`: 624 getnext() 호출 후 state → 다음 `r.random()` = 관측 마지막 이후 첫 번째 값.

## 다른 Z3 모델 (초기 state 복원 방식)

초기 seed state에서 여러 twist를 거쳐 관측값에 제약. 수학적으로 동일하나 더 느리고 twist 수 계산 주의 필요.

```python
# n_tw = (n_obs * 2 // 624) + 2  # 충분한 twist 횟수
# → outs[2*i], outs[2*i+1]에 제약
# setstate((3, tuple(state0 + [624]), None))  # index=624: 최초 seed 상태
```

이 방식 사용 시 `setstate` index = **624** (twist 트리거), skip = n_obs만큼 advance 필요.

## 연속 관측이 아닌 경우 (일부 비트만 leak)

score formula 등으로 `int(2^53 * x)` 의 일부만 공개될 때:
- 53비트 미만 leak → 관측 수가 더 많이 필요 (1400+)
- 제약: `LShR(temper(out), shift) == partial_value`

## 실전 예시 (Probability — SEETF 2022)

- 1337라운드 블랙잭, 모든 draws(player + dealer) 출력 → 전체 53비트 leak
- threshold 0.57 전략으로 ~181라운드 플레이 → 624 floats 수집
- Z3로 state 복원 → 미래 draws 완전 예측 → graph DP로 최적 경로 계산
- 결과: 825+/1337 wins deterministically

## 공통 함정

1. **N=312로 충분하다고 가정** → under-determined, Z3 sat이지만 틀린 state (Z3가 임의 solution 반환)
2. **Twist를 functional 방식으로 모델링** (in-place 무시) → phase 2와 last element 오류
3. **초기 state 방식에서 setstate index 혼동**: seed state면 index=624, getnext() 큐 방식이면 index=0
4. **training sample으로 검증** → obs[0]은 항상 constraint에 포함되어 있어 검증 의미 없음. 반드시 미관측 미래 값으로 검증
