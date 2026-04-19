---
name: numpy-mt-32bit-seed-brute
description: numpy.random.seed(n) with 32-bit n sets state[0]=n directly. First random.bytes(16) = 4 uint32 LE after single twist. Brute force 2^32 seeds in numba ~2-3 min on 8 cores.
type: attack
---

# numpy MT 32-bit Seed Brute (import numpy as MT, Zh3r0 V2)

## 전제
`numpy.random.seed(n)` — n은 32-bit. 이후 `random.bytes(16)` 공개 → 시드 복원 필요.

## 핵심 관찰
- **numpy의 single-int seed path**: `state[0] = n` 그대로 (Python stdlib random처럼 init_by_array 안 씀). 뒤 state[i] = `1812433253*(state[i-1]^(state[i-1]>>30)) + i mod 2^32`.
- 시딩 직후 pos=624이므로 첫 read가 **twist를 1번** 돌리고 pos=0부터 tempered state 공급.
- `random.bytes(16)` = uint32 4개를 **little-endian**으로 pack.
- 따라서 `untemper(u_le[i])` = `state[i]_new` (post-twist), i=0..3.

## Twist formula (첫 4 워드)
```
state[i]_new = state[i+397]
             ^ (((state[i] & 0x80000000) | (state[i+1] & 0x7FFFFFFF)) >> 1)
             ^ (0x9908B0DF if (state[i+1] & 1) else 0)
```
→ state[0..3]_new는 **원본 state[0..4]와 state[397..400]**에만 의존.

## 브루트 전략
각 seed 후보:
1. state[0]=seed부터 iterate하여 state[0..400] 계산 (~400 mult-shift-xor)
2. twist 식으로 state[0..3]_new 계산
3. 4개의 untempered target과 전수 비교 (1개 match해도 continue, 4개 다 맞으면 확정)

## 성능
- Python + numpy 재시드 반복: 2^32 × 6µs = **425분** (불가능)
- **Numba @njit(parallel=True)**: 2^32 검사 **~3분** (8코어, ~15M seeds/sec)
- Short-circuit: state[0]_new만 먼저 체크하면 2^-32 확률로 1번만 풀 검증

## 레퍼런스 구현
```python
from numba import njit, prange
import numpy as np

MULT = 1812433253; MATRIX_A = 0x9908B0DF
UPPER = 0x80000000; LOWER = 0x7FFFFFFF

@njit(parallel=True, cache=True)
def brute(t0, t1, t2, t3):
    chunk = 1 << 16
    n = (1 << 32) // chunk
    out = np.full(n, np.uint64(-1))
    for idx in prange(n):
        for seed in range(idx*chunk, (idx+1)*chunk):
            states = np.empty(401, dtype=np.uint32)
            states[0] = np.uint32(seed)
            s = states[0]
            for i in range(1, 401):
                s = np.uint32(MULT * (s ^ (s >> 30)) + np.uint32(i))
                states[i] = s
            y = (states[0] & UPPER) | (states[1] & LOWER)
            m = MATRIX_A if (states[1] & 1) else 0
            if states[397] ^ (y >> 1) ^ np.uint32(m) == t0:
                # 3개 더 체크, 다 맞으면 out[idx] = seed
                ...
    # scan out for non-sentinel
```

## Untemper (standard MT19937)
```python
def untemper(y):
    # reverse y ^= y>>18
    y ^= (y >> 18)
    # reverse y ^= (y<<15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # reverse y ^= (y<<7) & 0x9D2C5680 (7 iter chain)
    for s in range(7):
        y ^= ((y << 7) & 0x9D2C5680) & (0xFF80 << (7*s))  # 단순화 버전은 bit-by-bit
    # reverse y ^= y>>11 (bit-by-bit)
    ...
```
정확한 bit-by-bit 구현 추천 (`mt_brute.py` 참고).

## 적용 대상
- numpy.random 시드가 32-bit entropy (`os.urandom(4)` 등)
- 첫 read 16 byte 이상이 공개
- Python stdlib `random`에는 **부적용** (init_by_array 경로로 seed → state 비자명)

## 주의
- Python 3의 `random.seed(int)`는 numpy와 다른 경로. 위 공격은 **numpy 전용**.
- 64-bit seed면 무력. 16-bit처럼 더 작으면 즉시.
- `random.bytes(n)` 사이에 다른 state 소비(`randint` 등) 있으면 offset 조정.
