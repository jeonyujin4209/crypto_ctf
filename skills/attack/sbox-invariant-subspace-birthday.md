---
name: sbox-invariant-subspace-birthday
description: SBOX에 invariant subspace(특정 비트=0이면 출력도 0)가 있으면 유효 state를 축소시켜 birthday 공격 가능
type: skill
---

## 상황

커스텀 SPN(Substitution-Permutation Network) 또는 sponge 해시에서 collision을 찾아야 하는데, state가 커서 직접 birthday가 불가능한 경우.

## 핵심 아이디어

SBOX가 **invariant subspace**를 가질 수 있다:
특정 비트 위치들의 값이 0이면, SBOX 출력에서도 그 비트들이 0으로 유지됨.

```python
# 예: bits 2, 4, 5 = 0이면 출력도 0
mask = 0x04 | 0x10 | 0x20
for x in range(256):
    if (x & mask) == 0:
        assert (SBOX[x] & mask) == 0  # invariant!
```

만약 **permutation 레이어가 bit index를 보존**한다면 (같은 bit position끼리만 자리바꿈), 이 invariant는 모든 라운드를 통해 전파된다.

## 공격 효과

| 원래 | invariant 적용 후 |
|------|-------------------|
| capacity 80비트 (10 bytes × 8 bits) | capacity 50비트 (10 bytes × 5 free bits) |
| birthday ~2^40 | birthday ~2^25 |

**유효 비트 = 전체 비트 - invariant 비트** → 지수적 축소.

## 공격 절차

### 1. SBOX 분석
```python
# 모든 가능한 bit mask에 대해 invariant 체크
for mask in range(1, 256):
    invariant = True
    for x in range(256):
        if (x & mask) == 0 and (SBOX[x] & mask) != 0:
            invariant = False
            break
    if invariant:
        print(f"Invariant mask: 0x{mask:02x} ({bin(mask).count('1')} bits)")
```

### 2. Permutation 호환성 확인
permute가 bit index를 보존하는지 확인. 즉 bit b of byte i → bit b of byte j (다른 bit으로 이동하지 않음).

### 3. 초기 state 확인
INIT의 capacity 바이트들이 이미 invariant를 만족하는지 확인:
```python
assert all((INIT[i] & mask) == 0 for i in range(rate_size, state_size))
```

### 4. 입력 제약
입력 블록에서 invariant 비트를 INIT과 맞춤 (XOR 후 0이 되도록):
```python
forced_bits = [INIT[i] & mask for i in range(rate_size)]
# 각 입력 바이트에서 forced_bits는 고정, 나머지만 자유
```

### 5. Birthday 공격
축소된 capacity에 대해 birthday:
```python
# numpy 배치로 고속화
states = batch_hash(random_blocks)  # 200K/batch
cap_key = bytes(state[capacity_start:capacity_end])
# dict에 저장, collision 탐색
```

### 6. 2-block collision 구성
capacity collision 발견 후:
```
msg1 = block_a + c
msg2 = block_b + (c ⊕ rate_a ⊕ rate_b)
```

## 탐지 체크리스트

1. ☐ 커스텀 SPN/sponge 해시인가?
2. ☐ permute가 bit index를 보존하는가? (bit b → bit b, 바이트만 이동)
3. ☐ SBOX에 non-trivial invariant mask가 있는가?
4. ☐ INIT capacity가 invariant를 만족하는가?
5. ☐ 축소된 capacity로 birthday가 실현 가능한가?

## 실전 예시: SpongeBob (HTB Cyber Apocalypse 2021)

- Sponge: 18-byte state, 8-byte rate, 10-byte capacity
- Permute: 8개 bit-plane 독립 permutation → bit index 보존
- SBOX: bits 2,4,5=0 → 출력도 0 (3비트 invariant)
- 유효 capacity: 10×5 = 50비트 (80→50)
- Birthday: 2^25 ≈ 33M hashes, numpy 배치로 ~65초

## 공통 함정

1. **SBOX만 보면 안됨**: permute가 bit index를 보존하지 않으면 invariant가 다음 라운드에서 깨짐
2. **INIT 확인 필수**: capacity 초기값이 invariant를 안 만족하면 적용 불가
3. **입력도 제약**: XOR 후 state가 invariant를 만족해야 하므로 입력의 forced bits 계산 필요
