---
name: arora-ge-binary-lwe
description: Binary/bounded error LWE에서 error polynomial이 0 → monomial linearization으로 Gaussian elimination. 표준 lattice 공격보다 훨씬 빠름
type: skill
---

# Arora-Ge Linearization for Binary/Bounded LWE

## 유형
LWE (Learning With Errors) with errors from a small set (binary, ternary, bounded)

## Trigger 패턴
LWE 챌린지에서 error term이 다음 중 하나:
- **Binary**: `e_i ∈ {0, 1}`
- **Ternary**: `e_i ∈ {-1, 0, 1}`
- **Small bounded**: `|e_i| ≤ B` for small `B`

이때 표준 LWE 공격(BKW, primal/dual lattice)보다 **Arora-Ge linearization**이 훨씬 빠를 수 있음. 특히 `n` (dimension)이 작고 sample 수가 충분할 때.

## 왜 못 풀었나 (A)

### 시도 1: 직접 격자 환원 (LLL/BKZ)
binary error라고 LLL 돌려도 차원이 크면 short vector가 안 나옴. q가 큰 경우 더 어려움.

### 시도 2: BKW
샘플이 부족함. BKW는 보통 지수개 샘플 필요.

### 시도 3: Brute force secret
`s` 차원이 25만 돼도 `2^25 · sample_count`라 너무 느림. 더 큰 차원은 절대 불가.

### 핵심 깨달음
error space가 finite이면 **error 자체에 대한 다항식**이 0이 됨. 이걸 monomial로 linearize.

## 어떻게 해결했나 (B)

### Binary error case (`e ∈ {0, 1}`)
각 LWE sample `(a_i, b_i)`에 대해 `e_i = b_i - <a_i, s>`. 그러면:
```
e_i · (e_i - 1) = 0
⇔ (b_i - <a_i, s>) · (b_i - <a_i, s> - 1) = 0
⇔ <a_i, s>² - (2b_i - 1)<a_i, s> + b_i(b_i-1) = 0
```
이걸 `s_j` 와 `s_j s_k` 모노미얼로 전개하면 **2차 식**:
```
Σ_{j,k} (a_ij·a_ik) · (s_j·s_k) - (2b_i - 1) · Σ_j a_ij · s_j + b_i(b_i-1) ≡ 0 (mod q)
```

### Linearization
- 변수: `s_1, s_2, ..., s_n` (n개) + `s_j·s_k for j ≤ k` (`n(n+1)/2`개) → 총 `n + n(n+1)/2 ≈ n²/2` 모노미얼
- 각 sample → 1개 선형 식
- **샘플 ≥ 모노미얼 수**면 가우스 소거로 풀림
- 보통 `m ≥ n(n+1)/2 + n` 샘플 필요

### General `e ∈ {v_1, ..., v_d}` case
`Π_k (e_i - v_k) = 0` → degree-`d` 다항식 → degree-`d` monomial linearization. 모노미얼 수 `O(n^d)`로 폭증하므로 `d ≤ 3`이 실용적.

### 구현 스켈레톤
```python
import numpy as np

def arora_ge_binary(A, b, q, n):
    # m samples, n-dim secret, binary error
    m = len(b)
    num_mono = n + n*(n+1)//2  # linear + quadratic
    M = np.zeros((m, num_mono + 1), dtype=object)  # +1 for constant
    
    def mono_idx(j, k=None):
        if k is None:
            return j  # s_j
        j, k = sorted([j, k])
        return n + j*(2*n - j - 1)//2 + (k - j)
    
    for i in range(m):
        # quadratic part: Σ a_ij a_ik · s_j s_k
        for j in range(n):
            for k in range(j, n):
                coeff = A[i,j] * A[i,k]
                if j != k:
                    coeff *= 2  # s_j s_k = s_k s_j
                M[i, mono_idx(j, k)] += coeff
        # linear part: -(2b_i - 1) Σ a_ij s_j
        for j in range(n):
            M[i, j] -= (2*b[i] - 1) * A[i, j]
        # constant
        M[i, -1] = b[i] * (b[i] - 1)
    
    M = M % q
    # Gaussian elimination over GF(q)
    s = solve_linear_mod(M[:, :-1], -M[:, -1], q)
    return s
```

### 핵심 튜닝
1. **샘플 개수**: 모노미얼 수보다 충분히 많아야 unique solution. 보통 `1.5 × num_mono` 이상
2. **q는 prime**이어야 가우스 소거 깔끔. composite면 CRT 분해
3. **Degree control**: ternary `{-1, 0, 1}`은 cubic `e(e-1)(e+1)=0`이라 모노미얼 폭증. n 작아야 실용적
4. **Sparse case**: secret도 sparse / binary면 추가 제약 활용 가능

## 적용 범위
- Binary / ternary error LWE
- Bounded uniform error (작은 B)
- Regev encryption with small noise
- 일반적으로 "error가 finite small set에서 sample"인 모든 LWE 변형
- **n이 작거나 (≤50) 아니면 sample이 매우 많을 때** 특히 강력

## 출처
- CryptoHack: Bounded Noise (50pts, Lattices / LWE 2)
  - n=25 dim, binary error, 625 samples → 351 monomials
  - F_65537에서 단순 가우스 소거로 끝
- 원논문: Arora & Ge, "New Algorithms for Learning in Presence of Errors" (ICALP 2011)

## 메모
- 모노미얼 수가 너무 많으면 fail → degree 줄이거나 차원 줄이는 sub-problem 찾기
- error가 정말 binary 아니라 "거의 binary + 가끔 outlier"면 → robust 변형 필요 (RANSAC-like)
