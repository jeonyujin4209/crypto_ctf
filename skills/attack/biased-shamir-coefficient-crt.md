---
name: biased-shamir-coefficient-crt
description: Shamir SSS coefficients sampled from [0, p-2] (off-by-one) leak secret. Pick p just above n, n=p-1; constraint a_k != p-1 mod p enumerates ~p/3 secret candidates per query. Intersect across queries → unique mod p; iterate primes; CRT.
type: attack
---

# Biased Shamir Coefficient Leak + CRT

## 시나리오
서버가 매번 같은 secret로 Shamir SSS poly를 샘플하고 n-1 share를 공개:
```python
self.poly = [secret] + [getRandomRange(0, self.p - 1) for _ in range(n - 1)]
# getRandomRange(0, p-1)은 [0, p-2] 범위. 절대 p-1 안 나옴!
```
공격자는 (p, n)을 자유롭게 고를 수 있고, 한 connection에서 여러 query 가능.

## 약점 핵심
일반적인 Shamir는 n-1 share로 secret information-theoretically secure. 그러나
계수가 [0, p-1) 가 아니라 [0, p-2]에서 sampling되면, "어떤 계수도 p-1 mod p가 되면 안 됨"이라는
constraint가 secret 분포를 균등에서 어긋나게 만든다.

## 분석
n-1 share가 주어지면 missing share `s_n` 모르는 상태. Lagrange로:
```
a_k = sum_i s_i * L_i^{(k)}(0)   (k번째 계수, 단 사실은 x^k 계수)
    = fixed[k] + s_n * B[k]   (mod p)
```
즉 모든 a_k는 s_n의 affine fn. 각 k=1..n-1에 대해 `a_k != p-1` 제약은
s_n의 1개 값 제거 (B[k] != 0일 때). 총 n-1 제약으로 최대 n-1 값 제거.

**경험적 관찰**: p=n+1로 잡으면 이론상 secret 후보 ~2개지만 실제 ~p/3개.
(B[k]=0인 경우, 동일 s_n이 여러 constraint에 trip되는 경우 등으로 제거가 부족).

## 공격 절차
1. 작은 prime list 선택 (prod > 2^|secret|). 예: 17, 19, 23, ..., 223 (42개로 273-bit).
2. 각 p마다 n = p-1 로 max info per query.
3. 각 query: 받은 share에 대해 모든 s_n ∈ [0, p) 순회, 모든 (k>=1)에 대해
   `(fixed[k] + sn*B[k]) % p != p-1` 만 통과시켜 candidate `a_0` 모음.
4. 여러 query의 candidate set 교집합으로 narrow → 보통 5~10 query면 unique.
5. CRT로 `secret mod prod(p_i)` 복구.

## 핵심 트릭: pipelining
Server `signal.alarm(30)` 짧음. RTT-bound. 해결:
- 모든 (p_i, n_i) batch를 socket에 한 번에 push (TCP buffer가 받음)
- 그 다음 모든 response를 sequential read
- batch=8 query/prime → 42 primes × 8 = 336 query를 ~7s에 완료
- 일부 prime이 8 query로 unique 안 되면 retry round (몇 개만 남음)

## 코드 스니펫 (candidate enumeration)
```python
def candidates_from_shares(partial_shares, p, n, Lcoeffs):
    fixed = [sum(partial_shares[i] * Lcoeffs[i][k] for i in range(n-1)) % p
             for k in range(n)]
    B = [Lcoeffs[n-1][k] for k in range(n)]
    cands = set()
    for sn in range(p):
        if all((fixed[k] + sn * B[k]) % p != p-1 for k in range(1, n)):
            cands.add((fixed[0] + sn * B[0]) % p)
    return cands
```

## 정보량 추정
- 단일 query 정보 = log2(p / |valid set|) ≈ log2(3) ≈ 1.6 bits
- 256-bit secret 복구에 ~160 query 이론적 minimum (info bound)
- prime 선택은 |valid|/p 비율에 큰 영향 없음 → smallest primes로 prod 채우는 게 효율

## 함정
- **Shares는 n-1개만 주어짐** (server가 `shares[:-1]` 반환). 코드의 `partial_shares`는 길이 n-1.
- **batch에서 early break하면 alignment 깨짐**: 모든 prime마다 정확히 BATCH_PER_PRIME 슬롯 소비해야 함.
- **getRandomRange(a, b)는 range [a, b-1]**. 다른 lib (random.randrange)와 헷갈리지 말 것. PyCryptodome 컨벤션.

## 일반화
"계수 분포가 p보다 1만큼 짧다" 같은 1bit 누설도 충분: linear constraint로 환원, CRT.
다른 변형: bias가 [0, p/2)면 더 강한 누설; 비균등 PRNG면 likelihood 가중치.

## 사례
- HITCON CTF 2023 / cryptohack archive 12739 "Share" (`flag: even_off_by_one_is_leaky_in_SSS`)

## 관련
- `tools/try-first-principle` — 이론 추정 ("p/(p-n+1)≈1") 대신 실측 (p/3) 발견
- `tools/local-first-debugging` — local server로 protocol 디버깅 후 실서버 단발 성공
