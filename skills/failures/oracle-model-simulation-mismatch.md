# Oracle Model ≠ Simulation: 범위 조건 불일치

type: failure
tags: [oracle, simulation, carry, boundary, padding-oracle]

## 실수 패턴

오라클 응답을 시뮬레이션할 때, 파라미터 범위에 따라 오라클 동작이 달라지는 경우를 무시하고 한 가지 경우만 구현.

## 사례: Paillier carry oracle

오라클의 실제 동작 (3가지 경우):
1. **no carry** (S + delta < 256^128): separator 유지 → 항상 😀
2. **carry + has_zero**: separator 파괴되지만 remainder에 \x00 → 😀
3. **carry + no_zero**: separator 파괴, remainder에 \x00 없음 → 😡

시뮬레이션에서의 실수:
- **optimize_fast.py** (numpy): `(S+d) mod 256^128`의 has_zero_byte를 무조건 계산 → case 1을 무시
- **build_fingerprint_table**: carry일 때만 has_zero 체크 → case 1에서 bit=0 (실제론 😀=bit 1)

결과: mixed zone delta `[BYTE128-s_max, BYTE128-s_min]`에서 시뮬레이션과 실제 오라클이 불일치 → 36% unique (서버에서 즉시 실패)

## 해결

delta 범위를 **all-carry zone** `[BYTE128-s_min, 2*BYTE128-s_max]`로 고정하면 case 1이 발생 불가 → 세 구현 모두 일치 → 88% unique.

## 범용 교훈

오라클 시뮬레이션 코드를 작성할 때:
1. 파라미터 범위별 오라클 동작을 **전부** 열거 (case analysis)
2. 시뮬레이션이 **모든 case를 정확히 반영**하는지 확인
3. 가능하면 불필요한 case를 **파라미터 범위 제한**으로 제거 (all-carry zone처럼)
4. 서버 실행 전에 **시뮬레이션 vs 로컬 서버** 교차검증
