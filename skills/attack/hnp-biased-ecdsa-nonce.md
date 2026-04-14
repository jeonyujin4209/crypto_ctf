---
name: hnp-biased-ecdsa-nonce
description: Biased ECDSA nonce(MSBs=0) → Hidden Number Problem → Boneh-Venkatesan lattice 공격. Sage 없으면 pure-Python LLL
type: skill
---

# HNP Lattice Attack on Biased ECDSA Nonces

## 유형
ECDSA / DSA signature with biased (short) nonce → Hidden Number Problem

## Trigger 패턴
다음 중 하나가 보이면 즉시 HNP 격자 의심:
- nonce `k`가 `q`보다 명백히 작음 (예: SHA-1 nonce를 P-256에서 사용 → 160-bit < 256-bit q)
- nonce가 시간/카운터/짧은 PRNG 출력에서 유도됨
- 여러 서명을 모을 수 있음
- 메시지 해시 `h`, 서명 `(r, s)`, 공개키 `Q = dG`가 주어짐

**핵심 식**: `s ≡ k⁻¹(h + rd) mod q`  →  `k ≡ s⁻¹·h + s⁻¹·r·d (mod q)`
즉 `k = t + a·d (mod q)` 형태인데 `k`가 작으면 `d`에 대한 HNP 인스턴스.

## 왜 못 풀었나 (A)

### 시도 1: 직접 brute force / sympy
nonce가 96-bit만 작아도 `2^96` brute force는 불가능.

### 시도 2: SageMath의 LLL 호출
**SageMath가 없는 환경**. `fpylll`도 없음. 결국 직접 LLL 구현 필요.

### 시도 3: 잘못된 weight
격자 행렬에 weight `W = q`로 시작 → LLL이 trivial vector만 출력. 너무 작아도 안 됨, 너무 커도 안 됨.

### 시도 4: 행렬 차원 부족
2~3개 서명만으로 HNP → short vector가 안 나옴. 5개 이상 필요.

## 어떻게 해결했나 (B)

### 격자 구성 (Boneh-Venkatesan 임베딩)
n개 서명 `(r_i, s_i, h_i)`에 대해:
```
A_i = s_i⁻¹ · r_i mod q
B_i = s_i⁻¹ · h_i mod q
```
그러면 `k_i ≡ B_i + A_i · d (mod q)`, 즉 `k_i = B_i + A_i·d - q·m_i` (적절한 정수 m_i).

격자 (n+2 차원):
```
B = [ q·I_n        0     0  ]    ← n행: q·e_i
    [ A_1..A_n     W     0  ]    ← d 변수
    [ B_1..B_n     0     W  ]    ← 상수항
```
LLL 후 short vector에서 `(k_1 - q·m_1, ..., k_n - q·m_n, W·d, W)` 패턴 찾음.

### 핵심 튜닝 포인트
1. **Weight**: `W ≈ 2^bit_length(k)`. nonce가 160-bit면 `W = 2^159` 정도
2. **차원**: 최소 4~5개 서명. bias가 작을수록 더 필요
3. **Centering**: `k`를 `[-q/2, q/2]` 범위로 center하면 short vector 더 잘 잡힘
   ```python
   B_i_centered = B_i - q//2  # 또는 -2^(bitlen-1)
   ```
4. **Recovery**: short vector의 마지막 두 성분이 `(±W·d, ±W)` → `d = component / W` (sign 양쪽 다 시도)

### Pure Python LLL fallback
```python
from fractions import Fraction

def lll(B, delta=Fraction(3, 4)):
    B = [list(row) for row in B]
    n = len(B)
    # Gram-Schmidt with Fraction
    def gso():
        Bs = [list(row) for row in B]
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            for j in range(i):
                mu[i][j] = sum(B[i][k]*Bs[j][k] for k in range(len(B[0]))) / sum(Bs[j][k]**2 for k in range(len(B[0])))
                Bs[i] = [Bs[i][k] - mu[i][j]*Bs[j][k] for k in range(len(B[0]))]
        return Bs, mu
    # ... (size reduction + Lovász condition loop)
```
Fraction 기반이라 느리지만 작은 차원 (≤10)은 충분히 빠름.

### 검증
recover한 `d`로 `Q' = d·G` 계산 → 주어진 `Q`와 일치하는지 확인. 안 맞으면 sign/centering 다시.

## 적용 범위
- ECDSA / DSA / Schnorr with short nonces
- ECDSA with prefix/suffix bias (`k = c || small`, `k = small || c`)
- "ECDSA + LCG nonce" 류
- 일반 Hidden Number Problem (Diffie-Hellman MSB leak 등)

## 출처
- CryptoHack: No Random, No Bias (120pts, Elliptic Curves Signatures)
  - SHA-1 nonce on P-256 → 96-bit bias
  - 5×4 lattice, W = 2^159, n=3 서명으로 충분

## 메모
- bias가 클수록 (k가 q에 비해 많이 작을수록) 적은 서명으로 풀림
- `2^(bit) < q`인데 정확한 bit 수가 모르면 여러 W 후보로 시도
- BKZ가 LLL보다 강력하지만 LLL로 보통 충분
