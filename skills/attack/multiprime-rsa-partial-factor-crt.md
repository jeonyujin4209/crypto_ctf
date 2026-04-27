---
name: multiprime-rsa-partial-factor-crt
description: Multi-prime RSA `N = prod p_i`에서 message `m`이 작으면 (bit_length(m) << bit_length(N)) 일부 p_i만 복구 → CRT로 m_i 결합 → m mod (prod 복구한 p_i) = m. 모든 인수 분해 불필요.
type: attack
---

# Multi-Prime RSA Partial Factorization + CRT (m << N case)

## 패턴
- N = p_1 · p_2 · ... · p_k (k 큰 다중 소수)
- c = m^e mod N
- **m << N**: message bit length이 N보다 훨씬 작음 (예: m=1024-bit, N=32000-bit)
- 일부 p_i만 brute-force/factoring으로 복구 가능, 나머지는 infeasible

이 때 **누적된 p_i 곱이 m을 초과하면** 전체 factorization 없이 m 복구 가능.

## 핵심 아이디어
복구한 소수 `{p_1, ..., p_t}`에 대해:
1. 각 p_i에 대해 `d_i = e^(-1) mod (p_i - 1)`
2. `m_i = c^{d_i} mod p_i = m mod p_i`
3. CRT로 `m_i`들을 `M = prod(p_i)` 모듈러스 위에서 결합
4. `M > m`이면 `m mod M = m` 직접 회수

## 전형적 트리거
- 다중 소수 RSA (multi-prime, 보통 R-prime RSA)
- 약한 PRNG로 소수 생성 → 일부 소수 brute force 가능
- `len(flag)` 작음 (예: 128 bytes = 1024 bits)

## 코드 패턴
```python
# Recover some primes via brute force / ECM / weak PRNG
primes = []
for s in range(SEED_LIMIT):
    p = recreate_prime(s)
    if N % p == 0:
        primes.append(p)
    # Stop when product exceeds m bound
    if prod(primes).bit_length() >= m_bits + 64:
        break

# CRT recover m
residues, moduli = [], []
for p in primes:
    if gcd(e, p-1) != 1:  # skip non-invertible
        continue
    d = pow(e, -1, p-1)
    residues.append(pow(c, d, p))
    moduli.append(p)

# Standard CRT
M = prod(moduli)
m = sum(r * (M//p) * pow(M//p, -1, p) for r, p in zip(residues, moduli)) % M
```

## 이 패턴이 적용된 챌린지
- **RRSSAA (ECSC 2023)**: N = prod(get_prime(i) for i in range(2, 128)), 각 prime의 seed가 randbelow(2**i) — i=2..16에서 brute 가능. 5개 prime만 있어도 product > 2^1024 = m bound. Flag 1024-bit.

## 함정
- `gcd(e, p-1) != 1`인 경우 e 비가역 → 그 prime은 skip (드물지만 발생 가능)
- M이 m보다 약간만 커도 안전 (보통 +64 bit margin 권장)
- 너무 많은 prime을 모으면 시간 낭비. m bit + 작은 margin이면 충분

## 관련
- `partial-pohlig-hellman-bounded-key` — DLP 버전: secret이 group order보다 작은 경우
- `hastad-small-message-broadcast` — small e에서 m broadcast 공격 (관련 idea: m << N)
