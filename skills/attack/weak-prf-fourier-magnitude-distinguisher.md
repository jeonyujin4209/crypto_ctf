---
name: weak-prf-fourier-magnitude-distinguisher
description: Weak PRF 출력 marginal이 uniform처럼 보이지만 key의 prod 분포가 집중 → mod-q 거친 output에 Fourier coefficient bias. |F_k|^2 테스트로 uniform random vs real PRF 구별. Chi-square보다 강력
type: attack
---

# Fourier Magnitude Distinguisher for "Uniform-Marginal" Weak PRFs

## 유형
PRF `f(x) ∈ {0, 1, ..., q-1}` with:
- Naive chi-square: 거의 uniform → 구별 불가
- 그러나 특정 Fourier 계수 `F_k = E[ω^(kf)]` (ω = e^{2πi/q})가 **non-trivial magnitude**를 가짐

전형적 상황:
- `f(x) = (prod(x) mod p + prod(x) mod q) mod p`, small p,q (5, 7 등)
- `prod = <key, hash(x)_bits>` — random key + random hash → prod ~ Binomial(hw, 1/2) 집중 분포
- Hash가 output을 거의 uniform하게 보이지만 joint bias 있음

## 왜 chi-square로 안 되나
- 각 output value의 marginal 확률이 1/5 ± 0.02 정도 매우 작은 bias
- 64 rounds * 30 queries 내에서 chi-square는 50% 근처 error rate

## 핵심 아이디어: Fourier coefficient 크기
`ω = e^{2πi/q}`로 `Z_k = Σ ω^(k * f(x_j))` 계산.
- Under mode 1 (uniform): `E[Z_k/N] = 0`, `E[|Z_k/N|^2] = 1/N` (exponential distribution)
- Under mode 0 (real PRF): `|Z_k/N|^2 → |F_k|^2 + 1/N`

만약 `|F_k|^2 ≈ 0.01` (특정 k에서), 그리고 N=5000이면:
- Mode 1: `|Z_k/N|^2 ~ Exp(1/N = 2e-4)` → P(>0.003) = e^{-15} ≈ 3e-7
- Mode 0: mean ≈ 0.01, std ≈ sqrt(2*|F_k|^2/N) ≈ 0.002 → P(<0.003) ≈ 0.1%

**threshold 0.003에서 거의 완벽한 구별**. 64 라운드 모두 성공 가능.

## 어떤 k를 쓰나
실험 (랜덤 key 20+ 시뮬): 어떤 Fourier index `k`가 large `|F_k|^2`를 주는지 확인.
- Mod-5 output, `p=5, q=7` PRF: k=2의 `|F_2|^2 ≈ 0.007-0.011` (consistent across keys)
- k=1, 3, 4는 훨씬 작음 (0.0005 수준)

**일반적으로**: 가장 큰 Fourier coefficient는 mod value와 관련 있음. `|F_k|^2`를 경험적으로 측정해서 큰 것 선택.

## 구현

```python
import cmath, math
OMEGA = cmath.exp(2j * math.pi / 5)

def distinguish(outputs, threshold=0.003, k=2):
    """outputs: list of PRF output values 0..4. Returns 0 (real) or 1 (random)."""
    N = len(outputs)
    omegas = [OMEGA ** (k * v) for v in range(5)]
    Z = sum(omegas[v] for v in outputs)
    mag_sq = (Z.real ** 2 + Z.imag ** 2) / N**2
    return 0 if mag_sq > threshold else 1
```

## N 선택
`|F_k|^2 ≈ 0.01`일 때:
- N=1000: |F|² vs 1/N=0.001 → SNR 10, 99% accuracy per round
- N=5000: SNR 50 → 99.99%+
- 64 rounds이면 N=5000 권장 (누적 성공률 ~99%)

## 왜 Parseval이 도움이 되나
Parseval: `Σ |F_k|² (k≠0) = 5 * Σ (p(v) - 1/5)²` = 5 × chi-square-like statistic.

특정 `|F_k|²` 하나 골라 쓰면 전체 chi-square보다 power가 높음 (다른 k들 noise 빼고 signal만 탐지).

## 경험적 측정 코드

```python
import random, hashlib
random.seed(42)

def measure_Fk(q_out, N=10000, trials=30):
    """Returns mean and spread of |F_k|^2 for candidate PRF."""
    results = []
    for _ in range(trials):
        key = generate_random_key()
        counts = [0] * q_out
        for xi in range(N):
            counts[real_prf(key, xi)] += 1
        probs = [c/N for c in counts]
        for k in range(1, q_out):
            F_k = sum(p * OMEGA**(k*v) for v, p in enumerate(probs))
            # record |F_k|^2
    return {k: (mean, min, max) for k in 1..q_out-1}
```

Run once offline → 최대 `|F_k|²`를 주는 k 선택, threshold 설정.

## 적용 가능
- Weak PRF with `f: X → {0, .., q-1}`, marginal ~ uniform but joint-biased
- `(a mod p + a mod q) mod p` 류 구조 (p, q small coprime)
- LPN/LWE 변형에서 error 분포가 Binomial-like로 집중된 경우

## 적용 불가
- Marginal 분포가 TRULY uniform (Fourier 계수 0) — 이 경우 joint를 봐야 함
- 너무 큰 q (5000 samples로도 signal 부족)
- 쿼리 수가 극히 적을 때 (N < 100)

## 출처
- CryptoHack CTF Archive 2022: Dark Arts (CODEGATE 2022) Generator2
  - p=5, q=7, hashed bits 256, random key 256 bits
  - `|F_2|^2 ≈ 0.007-0.011` across keys (measured)
  - N=5000 queries per round, threshold 0.003 → 64 rounds 모두 성공
- Parseval 기반 chi-square 관점: `Σ |F_k|² (k≠0) = q * var(marginal)`, so 단일 |F_k|² 사용은 "가장 signal 많은 차원" 선택
