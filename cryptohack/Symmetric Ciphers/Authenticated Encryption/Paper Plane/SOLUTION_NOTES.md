# Paper Plane (120pts) - Padding Oracle on AES-IGE

## 문제
- AES-IGE (Infinite Garble Extension) 모드 구현
- `encrypt_flag()`: FLAG 암호화 → ciphertext, m0, c0 반환
- `send_msg(ct, m0, c0)`: 복호화 후 PKCS7 검증 → valid/invalid 반환
- **패딩 오라클 존재**: valid/invalid 응답 차이로 plaintext 복원 가능

## IGE 모드 구조
```
암호화: x = block XOR c_prev → AES_enc(x) → result XOR m_prev
복호화: x = block XOR m_prev → AES_dec(x) → result XOR c_prev = plaintext
```
- m_prev: 이전 블록의 평문 (첫 블록은 m0)
- c_prev: 이전 블록의 암호문 (첫 블록은 c0)

## 풀이: 단일 블록 패딩 오라클
```
send_msg(target_block, m0, c0_test)
→ intermediate = AES_dec(target_block XOR m0)  ← m0 고정이면 동일
→ plaintext = intermediate XOR c0_test         ← c0_test 변조로 제어
→ PKCS7 검증
```
c0를 변조하면 CBC 패딩 오라클과 동일한 구조.

## Flag
`crypto{h3ll0_t3l3gr4m}`

---

## AI(Claude) 실패 과정 분석

### 시도 1: 기본 패딩 오라클 (실패)
```python
# byte 15에서 verify 로직 오류
if pos == 15:
    verify_c0 = bytearray(test_c0)
    verify_c0[14] ^= 1
    if not oracle(..., bytes(verify_c0)):
        # pad=0x01 확인
```
**실패 원인**: pad=0x01인 경우만 고려. guess=0x0f가 유일하게 valid인데, verify에서 byte 14를 flip하면 pad가 깨져서 항상 실패 → "Failed at byte 15"

**핵심 오해**: byte 15에서 valid guess가 1개뿐일 때, 그게 pad=0x01이 아닐 수 있다는 걸 처리 못함.

### 시도 2: verify 제거 후 재시도 (실패)
```python
if not found and pos == 15:
    # verify 없이 첫 번째 valid 수용
    for guess in range(256):
        if oracle(...):
            intermediate[pos] = guess ^ pad_val
```
**실패 원인**: pad_value를 1로 하드코딩. 실제로는 guess=0x0f일 때 pad_value가 1이 아닐 수 있음 (intermediate의 다른 바이트들이 우연히 같은 값을 가지면 더 큰 pad로 인식).

### 시도 3: pad_value 자동 판별 (성공)
```python
def find_pad_value(block, m0, guess_byte15):
    for pad_test in range(1, 17):
        idx = 16 - pad_test - 1
        test_c0 = bytearray(16)
        test_c0[15] = guess_byte15
        test_c0[idx] ^= 1
        if not oracle(...):
            continue  # 이 바이트도 pad의 일부
        else:
            return pad_test  # 이 바이트는 pad가 아님
```
**성공 이유**: pad 영역 바깥의 바이트를 flip해서 padding이 깨지는지 확인. 깨지면 그 바이트가 pad에 포함된 것이고, 안 깨지면 바깥 → pad 크기 판별.

### 실패 패턴 요약

| 시도 | 문제 | 근본 원인 |
|------|------|----------|
| 1 | byte 15 verify 실패 | pad=1만 가정, 다른 pad값 미고려 |
| 2 | pad_value 오판 | pad_value 하드코딩 (1) |
| 3 | 성공 | pad_value 동적 판별 |

### AI가 놓친 핵심 포인트
1. **c0의 다른 바이트가 0x00일 때, intermediate 값이 우연히 같은 값을 가지면 pad > 1이 됨**
   - c0 = [0x00]*15 + [guess] → pt[k] = inter[k] for k<15
   - 만약 inter[14] == inter[15] ^ guess (= pad_value) 이면 pad=2로 인식
   
2. **CBC 패딩 오라클의 "byte 15 edge case"는 잘 알려진 문제**이지만, IGE에서도 동일하게 적용된다는 걸 바로 연결 못함

3. **디버깅 접근이 비효율적** - 서버에 256*3 = 768회 요청으로 디버깅. 로컬 시뮬레이션을 먼저 했으면 요청 0으로 해결 가능했음

### 교훈
- 패딩 오라클에서 byte 15는 항상 특별 처리 필요 (pad value 불확실)
- 서버 테스트 전 로컬에서 edge case 검증하는 게 효율적
- IGE 모드는 CBC와 유사하지만 m0/c0 두 개의 IV가 있어서 어떤 걸 고정하고 어떤 걸 변조할지 먼저 결정해야 함
