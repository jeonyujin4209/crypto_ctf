---
name: popcount-hidden-bit-shifts
description: 수식 `x - Σ_{i>=1} floor(x/2^i)` = `popcount(x)`. 비트-쉬프트 합 위장된 함수 만나면 popcount 의심. f(A_i AND B) = popcount(A_i & B)는 선형(GF(2)/Z) 형태.
type: attack
---

# `x - Σ (x >> i)` = popcount(x)

## 정체

수식:
```python
def happiness(x):
    return x - sum(x >> i for i in range(1, x.bit_length()))
```
또는 유사 변형 (`x + 1 - bit_length(x) - ...`) 은 대개 **popcount**의 위장.

## 증명

`x = Σ_{k=0}^{L-1} b_k · 2^k` (L = bit_length(x), b_{L-1}=1). 그러면:
```
floor(x/2^i) = Σ_{k=i}^{L-1} b_k · 2^{k-i}
Σ_{i=1}^{L-1} floor(x/2^i) = Σ_{k=1}^{L-1} b_k · Σ_{i=1}^{k} 2^{k-i}
                           = Σ_{k=1}^{L-1} b_k · (2^k - 1)
                           = (x - b_0) - (popcount(x) - b_0)
                           = x - popcount(x)
```
따라서 `x - Σ floor(x/2^i) = popcount(x)`.

## 왜 위험한가

`encrypt(A, B) = [happiness(A_i AND B) for A_i in pubkey]` 같은 암호에서:
- `popcount(A_i AND B) = Σ_j A_{i,j} · b_j`  (A_{i,j} = bit j of A_i, b_j = bit j of B)
- **정수 선형 방정식**. m개 식 + n-bit B → 단순 선형대수.

m ≥ n이면 Gauss 소거로 풀림.
m < n (underdetermined) 이지만 b_j ∈ {0,1}이면 **binary ILP / LLL**로 풀림.

## 검출 패턴

- 수식에 `x >> i`, `x // 2**i`, `floor(x/2)` 루프 등장
- `bit_length`, `int_log2` 관련 sum/loop
- 결과가 작은 양수 (output ≤ bit_length of input)

자동 검증: `assert f(v) == bin(v).count('1')` for v ∈ {0, 1, 5, 255, 2**64+7, ...}.

## 적용 가능

- 비트 쉬프트 합/차이 조합으로 정의된 함수
- AND/OR + 이런 합성 → linear over-bit 구조 폭로

## 적용 불가

- 진짜 hash 같은 one-way 연산
- 쉬프트 결과가 원래 x의 "인덱스" 용도 (e.g., lookup table)

## 예: 다른 popcount 위장

| 식 | = |
|---|---|
| `x - sum(x >> i for i in range(1, L))` | popcount(x) |
| `sum((x >> i) & 1 for i in range(L))` | popcount(x) (직접) |
| `x + 1 - 2^L + sum(2^i - (x mod 2^{i+1}) for i)` | popcount 관련 |
| `2*x - (x XOR 1) - (x XOR 2) - ... ` | depends |

의심스러우면 **작은 x로 테이블 만들어 bin(x).count('1')과 비교**.

## 랜덤 패딩은 방어가 아님

**Revenge 함정**: `block = urandom(k1) ∥ msg ∥ urandom(k2)` 구조라도,
전체 block_int이 Z-linear 등식 `popcount(A_i & block_int) = c_i`에 들어가면
ILP가 **랜덤 패딩까지 전부 복구**한다 (정보량 충분할 때).
→ 고정 위치로 msg 슬라이스만 뽑으면 됨.

이유: 랜덤 패딩 비트도 미지수로 같이 풀린다. 등식 rank가 충분하면
모든 미지수가 pin down 됨 → "padding이 msg를 가려준다"는 직관 오류.

일반화: **bit-linear encryption에서 random padding은 security 추가 ≠ 0**.
보호하려면 비선형(XOR, MUX, bit rotate 의존) 도입 필수.

## 출처

- CryptoHack CTF Archive 2022: FaILProof (SekaiCTF)
  - `happiness(x) = x - Σ (x >> i)` → popcount
  - Encrypt = `[popcount(A_i AND B)]` = 128 정수 선형식 on 256 bin 변수
  - pulp binary ILP 0.22 s/block → 즉시 복구
- CryptoHack CTF Archive 2022: FaILProof Revenge (SekaiCTF)
  - sha256 → sha512, pubkey 128 (256-bit) → 256 (512-bit), block 32B → 64B (24 rand ∥ 8 msg ∥ 32 rand)
  - 동일 구조, ratio 1/2 유지 → ILP 0.85 s/block, 전체 512 bit 복구 후 bytes[24:32] 추출
  - 랜덤 패딩 방어 실패 사례
- 일반적 bit manipulation CTF 함정: SGP-CTF 계열에서 자주 등장
