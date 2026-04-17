---
name: aes-component-disable-key-recovery
description: AES 개별 컴포넌트(ARK/SB/SR/MC) 비활성화 시 각각의 약점 분석 + key 복구
type: skill
---

## 상황

AES-128 oracle에서 4개 컴포넌트(AddRoundKey, SubBytes, ShiftRows, MixColumns) 중 하나를 선택적으로 비활성화해서 encrypt 가능. 제한된 oracle call로 전체 key 복구.

## 컴포넌트별 약점 분석

### No AddRoundKey → key-independent (1 call)

ARK가 유일한 key mixing 단계. 비활성화하면 **어떤 key든 같은 ciphertext** 생성.

```python
# secret encrypt → ciphertext
# 아무 key(zero)로 decrypt (ARK도 skip) → plaintext = secret
cipher = AES(b'\x00' * 16)
cipher._add_round_key = no_op
plaintext = cipher.decrypt(ciphertext)
```

### No SubBytes → linear cipher (2 calls)

SB가 유일한 비선형 요소. 비활성화하면 전체가 GF(2^128) 위의 **아핀 함수**:

```
Enc_k(m) = S·m + T_k    (S: 고정 선형맵, T_k: key 의존 상수)
```

**XOR 상쇄 기법**: 임의의 key k'로 decrypt해도:
```
Dec_k'(Enc_k(0)) ⊕ Dec_k'(Enc_k(m)) = S^{-1}(S·m) = m
```
T_k' 항이 XOR로 상쇄되므로 **key를 몰라도 plaintext 복구 가능**.

```python
# Enc(0)과 Enc(secret) 두 번 query
cipher = AES(b'\x00' * 16)
cipher._inv_sub_bytes = no_op  # decrypt에서도 InvSB skip
secret = xor(cipher.decrypt(c0), cipher.decrypt(c1))
```

### No MixColumns → byte-level independence (65 calls)

MC가 column 내 byte diffusion 담당. 비활성화하면 **각 byte가 독립적으로 처리**.

단, ShiftRows가 라운드마다 위치를 돌리므로: **plaintext byte k → ciphertext byte (9k mod 16)**.

```python
# 64개 메시지로 256개 byte값 커버 (각 메시지에 4값씩)
for i in range(64):
    m = bytes([4*i + j%4 for j in range(16)])
    c = encrypt_no_mc(m)
    c_rearranged = bytes([c[9*k % 16] for k in range(16)])
    lookup[i] = c_rearranged

# secret ciphertext와 byte-by-byte 비교 → key byte 확정
```

위치 순열 `9k mod 16` 유도: column j는 ShiftRows에서 매 라운드 j칸 회전. 10라운드 후 row offset = 10*j mod 4. 이 구현의 state layout에서 position = row*4 + col → 순열이 9k mod 16으로 귀결.

### No ShiftRows → column independence (60 calls)

SR이 column 간 mixing 담당. 비활성화하면 **각 column(4 bytes)이 독립** 처리.

같은 byte 16개 반복 메시지 → 각 column에 같은 값. Secret ciphertext와 column 단위 비교:

```python
# 59개 lookup + 1 secret = 60 calls
candidates = [list(range(59, 256)) for _ in range(4)]  # 4 columns
for i in range(59):
    for col in range(4):
        if data_ct[i][4*col:4*col+4] == secret_ct[4*col:4*col+4]:
            candidates[col] = [i]

# 미매칭 column은 197 후보 → brute-force
# 2+ column 매칭 시 ≤ 197^2 ≈ 39K (feasible)
```

## 예산 분배

| 단계 | Oracle calls | Key bytes 복구 |
|------|-------------|---------------|
| ark secret | 1 | k[0:4] |
| sb data + sb secret | 2 | k[4:8] |
| mc data ×64 + mc secret | 65 | k[12:16] |
| sr data ×59 + sr secret | 60 | k[8:12] (partial + brute) |
| **합계** | **128** | **16 bytes** |

## 적용 조건 체크리스트

1. ☐ AES (또는 SPN) 개별 컴포넌트를 선택적 비활성화 가능?
2. ☐ Secret(key 파생) encrypt + data encrypt 모두 가능?
3. ☐ Oracle call 횟수가 128 이상?
4. ☐ Key schedule은 표준? (비표준이면 ARK 분석 달라질 수 있음)

→ 모두 예 → AES component disable key recovery 적용 가능

## 일반화: SPN에서 각 컴포넌트의 역할

| 컴포넌트 | 역할 | 비활성화 시 |
|----------|------|-----------|
| AddRoundKey | Key mixing (유일한 key 의존) | Key-independent → trivial decrypt |
| SubBytes | 비선형성 (S-box) | 전체 linear → 아핀 해석 |
| ShiftRows | Column 간 diffusion | Column 독립 → 4-byte 단위 분석 |
| MixColumns | Column 내 diffusion | Byte 독립 → 1-byte 단위 lookup |

## 공통 함정

1. **No-SB decrypt 시 `_inv_sub_bytes`도 no-op**: encrypt에서 SB skip이면 decrypt에서 InvSB skip
2. **No-MC에서 위치 순열 무시**: ShiftRows가 라운드마다 byte 위치를 돌림. 직접 추적하거나 9k%16 공식 사용
3. **SR brute-force 확률**: 4개 column 중 2개 이상 매칭이 ~20%. 실패 시 재접속 필요
4. **AES state layout**: 이 구현은 row-major (표준은 column-major). SR/MC 역할이 뒤바뀜에 주의
