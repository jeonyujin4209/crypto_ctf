# Padding Oracle: Byte 15 Edge Case

## 유형
Padding Oracle Attack (CBC, IGE 등 블록 암호 모드)

## 문제 상황
패딩 오라클 공격에서 마지막 바이트(byte 15)를 복원할 때, valid guess가 pad=0x01이라고 단정하면 실패한다.

## 왜 못 풀었나 (A)
byte 15에서 valid guess를 찾은 뒤, "이게 pad=0x01이 맞는지" verify하려고 byte 14를 flip했다. flip 후에도 valid이면 pad >= 2, invalid이면 pad=1로 판단하는 로직이었는데:

- c0의 나머지 바이트가 0x00이면, `pt[k] = intermediate[k]` (raw AES 출력)
- intermediate 값이 **우연히** 연속된 같은 값을 가지면 pad > 1로 인식됨
- 이 경우 verify에서 byte 14를 flip하면 pad가 깨져서 항상 invalid → "pad=1이 아님"으로 판단 → skip → 모든 guess 실패

```python
# 실패한 코드
if pos == 15:
    verify_c0[14] ^= 1
    if not oracle(verify_c0):  # 항상 여기 걸림
        intermediate[15] = guess ^ 1  # 도달 못함
```

## 어떻게 해결했나 (B)
pad_value를 가정하지 않고, **동적으로 판별**하는 함수를 분리했다.

```python
def find_pad_value(block, m0, guess_byte15):
    for pad_test in range(1, 17):
        idx = 16 - pad_test - 1  # pad 영역 바로 바깥 바이트
        if idx < 0:
            return pad_test
        test_c0 = bytearray(16)
        test_c0[15] = guess_byte15
        test_c0[idx] ^= 1  # pad 바깥 바이트 flip
        if not oracle(block, m0, test_c0):
            continue  # 이 바이트도 pad에 포함됨
        else:
            return pad_test  # 여기부터 pad 아님
    return 16
```

**원리**: pad 영역 바깥의 바이트를 flip해도 padding이 유지되면 → 그 바이트는 pad에 포함 안 됨 → pad 크기 확정.

## 적용 범위
- CBC 패딩 오라클
- IGE 패딩 오라클
- 기타 블록 암호 모드에서 PKCS7 패딩 오라클이 존재하는 경우
- **byte 15가 유일한 valid guess일 때 특히 중요**

## 출처
- CryptoHack: Paper Plane (120pts, Authenticated Encryption)
