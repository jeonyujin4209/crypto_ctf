---
type: attack
title: Patarin's Linearization Equation Attack on MI / MQ
tags: [multivariate, matsumoto-imai, MQ, linearization, GF2]
related: []
created: 2026-04-17
---

# Patarin's Linearization Equation Attack on MI / MQ

## 언제 쓸까

- 공개키가 **n개의 다변수 이차 다항식** (GF(2)^n → GF(2)^n)
- **Matsumoto-Imai (MI)** 구조: 중심맵 `P(x) = r·x^(q^θ+1)` over GF(q^n)
- 공개키 = `T ∘ φ⁻¹ ∘ P ∘ φ ∘ S` (S, T: 아핀변환)
- "substitution cipher" 또는 "multivariate" 키워드, 공개키가 MB 단위로 큼

## 핵심 아이디어

MI의 중심맵에서 Frobenius `x → x^q`가 **GF(q)-선형**이라는 점을 이용.

`b = r·a^(q+1)`에 `g(x) = x^(q-1)` 적용:

```
a·b^q = r^(q-1)·a^(q²)·b
```

좌변의 `b^q`와 우변의 `a^(q²)`는 Frobenius(선형). 따라서 `a`와 `b`의 좌표로 보면 **bilinear relation**:

```
Σ γ_{i,j}·x_i·y_j + Σ α_i·x_i + Σ β_j·y_j + δ = 0
```

이 관계는 **모든** (plaintext x, ciphertext y) 쌍에 대해 성립.

## 공격 절차

### 1. pt/ct 쌍 생성 ((n+1)² 개)
공개키로 직접 암호화하여 쌍 생성. **sparse 벡터** 사용 시 다항식 평가 고속화.

```python
from itertools import combinations

def gen_sparse_vectors(N, n):
    """0-bit, 1-bit, 2-bit, 3-bit ... 순서로 N개 생성"""
    vecs = [[]]
    for k in range(1, n):
        for c in combinations(range(n), k):
            vecs.append(list(c))
            if len(vecs) >= N:
                return vecs[:N]
    return vecs[:N]
```

### 2. Bilinear relation 행렬 구축
각 (x, y) 쌍에서 행 생성:

```
[x_0·y_0, ..., x_{n-1}·y_{n-1}, x_0, ..., x_{n-1}, y_0, ..., y_{n-1}, 1]
```

열 수: `n² + n + n + 1 = (n+1)²`. 행렬은 GF(2) 위 `(n+1)² × (n+1)²`.

**핵심 최적화**: sparse 벡터 x의 nonzero 위치 S에 대해 `y_int` 비트시프트로 행 구축:

```python
y_int = sum(Y[j] << j for j in range(n) if Y[j])
row = 0
for i in S:
    row |= y_int << (i * n)       # x_i·y_j 블록
    row |= 1 << (n*n + i)         # x_i
row |= y_int << (n*n + n)         # y_j
row |= 1 << (n*n + 2*n)           # δ
```

### 3. Right kernel 계산
numpy uint64 packed 행렬로 GF(2) RREF → nullity ≈ 2n (MI θ=1일 때).

```python
import numpy as np
NWORDS = (ncols + 63) // 64
M = np.zeros((nrows, NWORDS), dtype=np.uint64)
# ... 행 채우기 ...

pivots = []
pivot_row = 0
for col in range(ncols):
    w = col // 64
    b = np.uint64(1) << np.uint64(col % 64)
    col_slice = M[pivot_row:, w] & b
    nz = np.flatnonzero(col_slice)
    if len(nz) == 0:
        continue
    found = pivot_row + nz[0]
    if found != pivot_row:
        M[[pivot_row, found]] = M[[found, pivot_row]]
    elim = (M[:, w] & b).astype(bool)
    elim[pivot_row] = False
    if np.any(elim):
        M[elim] ^= M[pivot_row]
    pivots.append(col)
    pivot_row += 1
```

### 4. Ciphertext 대입 → 선형 시스템
각 kernel 벡터에 알려진 y 값 대입 → x에 대한 **선형 방정식** 획득:

```python
for kv in kernel_basis:
    coeff = 0  # x의 계수 (n-bit)
    for i in range(n):
        gamma_i = (kv >> (i * n)) & mask_n
        ai = bin(gamma_i & y_int).count('1') % 2
        ai ^= (kv >> (n*n + i)) & 1
        if ai:
            coeff |= 1 << i
    beta = (kv >> (n*n + n)) & mask_n
    b = bin(beta & y_int).count('1') % 2
    b ^= (kv >> (n*n + 2*n)) & 1
    # 방정식: coeff · X = b (GF(2))
```

80×80 가우스 소거 → 자유변수 있으면 2^d개 후보, printable ASCII 필터.

## 성능 참고

| n | 쌍 수 | 행렬 크기 | RREF 시간 |
|---|-------|-----------|-----------|
| 80 | 6561 | 6561×103 uint64 | ~8초 (numpy) |

- 다항식 파싱: ~1초 (1.2MB)
- sparse 암호화 6561회: ~0.3초
- 전체: **~10초**

## 흔한 실수

- `gcd(q+1, q^n - 1) > 1`이면 중심맵이 bijective 아님 → 복수 해 가능 (printable 필터 필요)
- Python 큰 정수 RREF는 느림 → **numpy uint64 packed** 사용 필수
- `1 << col` 대신 `np.uint64(1) << np.uint64(col%64)` 사용 (overflow 방지)
- Sage BooleanPolynomialRing 출력에서 다항식 분리: `, ` split (terms 내에 comma 없음)
