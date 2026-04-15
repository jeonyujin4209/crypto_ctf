---
name: custom-hash-xor-finalization-noop
description: 커스텀 해시 finalization이 고정 입력으로 같은 값을 짝수번 XOR하면 no-op → 충돌 난이도 대폭 하락
type: skill
---

## 상황

커스텀 해시 함수에 finalization 루프가 있지만, 루프 내부에서 사용하는 변수(대문자 X,Y,Z,U 등)가 갱신되지 않아 매 반복 동일한 값을 XOR 누적하는 경우.

## 핵심

`v ^= c`를 짝수번 반복하면 `v`는 원래 값으로 복원 (XOR self-inverse). **Finalization이 아무 효과 없음**.

```python
# 이런 패턴을 찾아라:
for i in range(4):  # 짝수번 반복
    RV1 ^= (x := f(X, Y, Z, U))  # X,Y,Z,U가 루프 내에서 불변
    # x는 매번 같은 값 → 4번 XOR = no-op
```

## 공격 전략

1. **Finalization 무효화 확인**: 대문자 변수가 루프 내에서 재할당되는지 확인. 안 되면 no-op.
2. **라운드 함수 충돌으로 환원**: 같은 길이 메시지에서 첫 번째 라운드 출력이 같으면, 이후 패딩이 동일하므로 전체 해시 충돌.
3. **Z3 bit-blast로 라운드 충돌 탐색**: 일부 입력 고정 + `Then('simplify','bit-blast','sat')` tactic.

## 체크리스트

- [ ] Finalization 루프에서 상태 변수 갱신 여부 확인
- [ ] XOR 누적 횟수가 짝수인지 확인
- [ ] 같은 길이 메시지 사용 (패딩 동일하게)
- [ ] 라운드 함수 입력 중 고정 가능한 변수 식별 → Z3 탐색 공간 축소

## 실전 예시 (Chaos — Zh3r0 CTF V2)

```python
# finalization: X,Y,Z,U (대문자)가 루프 내 불변 → 4회 XOR = no-op
for i in range(4):
    RV1 ^= (x := (X&0xffff)*(M-(Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A)
    # x,y,z,u (소문자)만 갱신되지만 수식에서 사용하는 건 X,Y,Z,U (대문자)
```

Z, U를 고정하고 Z3 bit-blast로 `round(X,Y,Z,U) = round(X',Y',Z,U)` 충돌을 2.6초에 발견.
