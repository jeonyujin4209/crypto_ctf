---
name: mt-state-partial-leak-z3
description: Partial bit leaks from random.random() → Z3로 MT19937 state 복원 (관측이 twist 경계를 넘어야 unique solution)
type: skill
---

## 상황

`random.random()`이 생성한 float의 일부 비트만 유출되는 시나리오. 예: score formula가 `int(2^53*x)`를 leak, 또는 일부 상위 비트만 공개.

`random.random()` 내부:
```c
a = genrand_uint32() >> 5   // 27 bits
b = genrand_uint32() >> 6   // 26 bits
return (a * 2^26 + b) / 2^53
```

→ 라운드당 27+26 = **53비트** leak, 11비트(5+6) hidden per MT-word pair.

## 핵심 조건 (왜 624개로 안 되나)

MT state = 624 × 32 = **19968 비트**. 라운드당 53비트 × N = 53N 비트 정보.

- N=312 (624 outputs, = 1 twist period): 53×312 = 16536 비트 < 19968. **under-determined**.
- N=500 (1000 outputs, 2 twists): 53×500 = 26500 비트. 이론상 충분하나 **2 twist 내에선 Z3가 unique 못 찾음**.
- **N≥700 (1400+ outputs, 3 twists):** 관측이 3번째 twist로 넘어가야 첫 twist state를 강하게 제약 → unique.

관측이 여러 twist 경계를 넘어야 linear system rank가 full이 됨.

## Z3 모델 (MT twist + tempering)

```python
from z3 import *
N_MT, M_MT = 624, 397
MATRIX_A = 0x9908b0df
UPPER_MASK, LOWER_MASK = 0x80000000, 0x7fffffff

def temper(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ LShR(y, 18)
    return y

def mt_twist_z3(state):
    """⚠️ Python/C MT twist는 in-place. Phase 2와 last element는 이미 업데이트된 new 참조!"""
    new = [None] * N_MT
    # Phase 1: i=0..226, mt[i+M]은 아직 구 값
    for i in range(N_MT - M_MT):
        y = (state[i] & UPPER_MASK) | (state[i+1] & LOWER_MASK)
        mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
        new[i] = state[i + M_MT] ^ LShR(y, 1) ^ mag
    # Phase 2: i=227..622, mt[i+M-N] = mt[i-227]은 **Phase 1에서 업데이트된 new** 참조
    for i in range(N_MT - M_MT, N_MT - 1):
        y = (state[i] & UPPER_MASK) | (state[i+1] & LOWER_MASK)
        mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
        new[i] = new[i + M_MT - N_MT] ^ LShR(y, 1) ^ mag
    # Last: i=623, mt[0]은 Phase 1에서 업데이트됨 → new[0] 참조 (★ 흔한 버그)
    i = N_MT - 1
    y = (state[i] & UPPER_MASK) | (new[0] & LOWER_MASK)
    mag = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
    new[i] = new[M_MT - 1] ^ LShR(y, 1) ^ mag
    return new

# 체인: 초기 state → 여러 번 twist → 각 twist의 state[i]에 대한 관측 제약
s = Solver()
states_orig = [BitVec(f's0_{i}', 32) for i in range(N_MT)]
all_outs = []
cur = states_orig
for _ in range(n_twists):
    cur = mt_twist_z3(cur)
    all_outs.extend(cur)

for i, x_53 in enumerate(pairs):
    a, b = x_53 >> 26, x_53 & ((1<<26)-1)
    s.add(LShR(temper(all_outs[2*i]),   5) == a)
    s.add(LShR(temper(all_outs[2*i+1]), 6) == b)

assert s.check() == sat
state = [s.model()[v].as_long() for v in states_orig]
```

## 복원된 state로 예측

```python
import random
rnd = random.Random()
rnd.setstate((3, tuple(state + [624]), None))
# 이미 소비한 N_LEARN 라운드만큼 advance
for _ in range(N_LEARN):
    rnd.random()
# 이제 서버와 동기 → 정확한 예측
```

## 실전 예시 (Real Mersenne — Zh3r0 CTF V2)

- 2000라운드 점수 게임, `score = 2^53/(int(2^53*x) - int(2^53*y))`
- y=0 보내면 denominator = `int(2^53*x)` 직접 노출
- 700라운드 learn (Z3 60s) → 1300라운드 × 1024 score ≈ 1.33M > 10^6

## 공통 함정

1. **N=312로 충분하다고 가정** → under-determined, Z3 sat이지만 틀린 state
2. **Twist를 naive한 functional 방식으로 모델링** (in-place 무시) → phase 2와 last element 오류
3. **Z3 SAT ≠ 정답**: rank 부족하면 Z3가 임의 solution 선택. 복원된 state를 실제 state와 비교 검증 필수
