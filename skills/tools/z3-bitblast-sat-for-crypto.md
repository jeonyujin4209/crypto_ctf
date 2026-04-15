---
name: z3-bitblast-sat-for-crypto
description: Z3 기본 solver가 bitvector 곱셈+XOR+회전 문제에서 타임아웃될 때 bit-blast+SAT tactic으로 극적 속도 향상
type: tool
---

## 상황

커스텀 해시/암호의 라운드 함수 충돌을 Z3로 찾을 때, 32-bit 곱셈 + XOR + 비트회전이 섞인 bitvector 문제에서 **기본 Solver()가 타임아웃** (2분+).

## 핵심

`Then('simplify', 'bit-blast', 'sat')` tactic을 사용하면 bitvector 문제를 SAT 인스턴스로 변환하여 SAT solver가 처리. 기본 solver 대비 **수십~수백배 빠름**.

## 패턴

```python
from z3 import *

# 기본 solver — 곱셈 포함 bitvector 문제에서 느림
# s = Solver()

# bit-blast + SAT — 극적 속도 향상
tactic = Then('simplify', 'bit-blast', 'sat')
s = tactic.solver()

s.add(...)  # bitvector constraints
result = s.check()  # 2min timeout → 2.6초
```

## 적용 조건

- 변수가 32-bit 이하 bitvector (총 128~256 bits)
- 정수 곱셈 `*`, XOR `^`, 비트회전 `RotateLeft/Right`, 시프트 `LShR` 혼합
- 가능하면 일부 변수를 concrete 값으로 고정하여 탐색 공간 축소

## 실전 예시 (Chaos — Zh3r0 CTF V2)

커스텀 해시 라운드 함수 충돌: `round(X,Y,Z,U) = round(X',Y',Z,U)` 에서 Z, U를 고정하고 X, Y, X', Y' (4×32=128 bits) 탐색.

```python
Z_concrete = 0xdeadbeef
U_concrete = 0xcafebabe

Xv, Yv = BitVec('X', 32), BitVec('Y', 32)
Xp, Yp = BitVec('Xp', 32), BitVec('Yp', 32)
Zz = BitVecVal(Z_concrete, 32)
Uz = BitVecVal(U_concrete, 32)

x1, y1, z1, u1 = round_func(Xv, Yv, Zz, Uz)
x2, y2, z2, u2 = round_func(Xp, Yp, Zz, Uz)

tactic = Then('simplify', 'bit-blast', 'sat')
s = tactic.solver()
s.add(x1 == x2, y1 == y2, z1 == z2, u1 == u2)
s.add(Or(Xv != Xp, Yv != Yp))
s.check()  # sat in 2.6s
```

## 주의

- 64-bit 곱셈이 포함되면 SAT 인코딩 크기가 급증하여 느려질 수 있음
- 변수를 줄일수록 빠름: concrete 값으로 고정 가능한 변수는 `BitVecVal`로 고정
