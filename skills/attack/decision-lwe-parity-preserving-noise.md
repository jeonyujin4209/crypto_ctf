---
name: decision-lwe-parity-preserving-noise
description: Decision-LWE에서 noise가 항상 even(또는 mod m=p^k의 어떤 subgroup에 갇힘) → mod m으로 reduce하면 noise=0. real/fake 구별이 일관성 체크로 환원. 추가로 dot(a,s) mod 2 = <a mod 2, s mod 2>이라 byte 비밀이 bit 비밀로 collapse
type: skill
---

# Decision-LWE with Parity-Preserving Noise → Clean Mod-2 LWE

## 유형
Decision-LWE 챌린지에서 noise 분포가 modular subgroup에 갇혀 있어, 적절한 mod로 reduce하면 noise가 사라지는 케이스.

## Trigger 패턴
- LWE-style oracle: `(a, b)` where `b = <a,s> + e (mod q)` for real, `b` random for fake
- noise generator를 자세히 보면 `e` 가 항상 어떤 subgroup에 속함:
  - `e |= bit; e <<= 1` 루프 마지막 shift는 LSB=0 강제 → e 항상 짝수
  - centered noise `e - C` 에서 `C` 도 짝수면 mod 2에서 사라짐
  - 일반화: `e ∈ k·Z/qZ` → mod (q/gcd(k,q))로 reduce

## 핵심 관찰
1. **Noise 격자 reduce**: `e ≡ 0 (mod m)`이면 `b ≡ <a,s> (mod m)` (no noise!)
2. **Real ↔ 일관성**: real row의 모든 sample이 동일 s로 mod-m equation을 만족.
   fake row는 mod-m에서도 random이라 consistency가 깨짐.
3. **Byte → Bit collapse (m=2)**: `dot(a, s) mod 2 = sum_j a_j * s_j mod 2 = sum_j (a_j mod 2)(s_j mod 2) mod 2`
   → 비밀의 entropy가 bit 단위로 축소. 16-byte secret → 16-bit unknown!

## 어떻게 푸나

### Step 1: noise 분석
`sample_noise()` 같은 함수의 출력을 작은 샘플로 enumerate해서 분포 직접 확인:
```python
vals = set(); 
for _ in range(100000): vals.add(sample_noise())
print(min(vals), max(vals), 'parity?', all(v % 2 == 0 for v in vals))
```

### Step 2: mod m equation 추출
real이라 가정하면 `b mod m = <a, s> mod m`. m=2면 한 비트씩.

### Step 3: real/fake 분류 + secret 복구
- 작은 unknown이면 (예: 16-bit) brute force 가능
- 큰 unknown이면 **information-set decoding 스타일**:
  - 여러 행에서 sample 묶어 over-determined 시스템 만들기 (`6k > 16` 면 OK)
  - 무작위 row subset에서 fake가 한 개도 없으면 시스템 일관 → 풀림
  - 검증: `s` 복구 후 모든 row에서 "6 sample 모두 일관" rate 측정. real → 100%, fake → 1/2^6
- k rows random subset이 모두 real일 확률 ≈ 2^-k (fake/real 50%일 때). k=6이면 1/64, 평균 64 trials.

### Step 4: flag 비트 분류
복구한 s로 각 row 검사:
- 6 sample 전부 mod-m equation 만족 → real → flag bit = 0 (또는 1, 도전 정의에 따라)
- 그렇지 않음 → fake → 반대 bit

## 구현 스켈레톤
```python
import numpy as np

# row_A: (R, 6, n) bit matrix; row_B: (R, 6) bit vector
def gf2_solve(A, b):
    M = np.concatenate([A, b[:,None]], axis=1).astype(np.uint8) % 2
    m, w = M.shape; n = w-1
    r = 0; piv = []
    for c in range(n):
        for k in range(r, m):
            if M[k,c]: M[[r,k]] = M[[k,r]]; break
        else: continue
        for k in range(m):
            if k != r and M[k,c]: M[k] ^= M[r]
        piv.append(c); r += 1
        if r == n: break
    if any(M[k,n] for k in range(r, m)): return None
    if len(piv) < n: return None
    x = np.zeros(n, dtype=np.uint8)
    for i,c in enumerate(piv): x[c] = M[i,n]
    return x

for trial in range(10**6):
    idxs = rng.choice(R, size=ceil(n/6)+1, replace=False)
    A = np.concatenate([row_A[i] for i in idxs], 0)
    b = np.concatenate([row_B[i] for i in idxs], 0)
    s = gf2_solve(A, b)
    if s is None: continue
    # verify: count rows with all-6 match
    ok = ((row_A @ s) % 2 == row_B).all(axis=1).sum()
    if ok > R//3:  # ~half should be real
        break
```

## 적용 범위
- LWE / Regev 변종에서 noise sampler가 algebraic 구조 (parity, divisibility)를 유지하는 모든 경우
- "sham vs real" decision oracle, m-of-n masking, sponge-with-bias 등
- Bit-level secret이 byte-level처럼 보이는 경우 (mod 2 collapse)

## 출처
- ECSC 2023 (Norway) "Tough decisions" — `e |= bit; e <<= 1`로 noise LSB=0 → mod 2 reduction. 16-byte key가 16-bit unknown으로 collapse, 296 rows 중 ~150 real, 6-row random subset solve로 즉시 복구.

## 메모
- 항상 `q = 256`, `q = 2^k` 같은 modulus의 **약수**로 reduce 시도하기. 큰 q에서 실패해도 작은 modulus가 풀림
- noise 분포에 다른 hidden 구조 (예: ternary `{-1,0,1}`, "centered" 음수)도 mod 3 / mod 2 reduce 후 살펴보기
- "real vs fake" decision은 `<a,s>` 일관성 검사로 환원. 6/6 match면 real, k/6 match면 fake (k 작을수록 확실)
