---
name: partial-pohlig-hellman-bounded-key
description: private key가 group order보다 작으면 Pohlig-Hellman에서 일부 prime factor만 풀어도 됨. CRT 모듈러스 > k bound이면 small brute force로 완성
type: skill
---

# Partial Pohlig-Hellman for Bounded Keys

## 패턴
- `g^k = pub`, g order = p₁·p₂····pₘ (서로소 factor)
- private key `k`가 **order보다 작게 제한됨** (bit size, 또는 특정 범위)
- 일부 pᵢ의 DLP가 feasible하고 나머지는 infeasible

이 때 **feasible한 pᵢ들만 풀어 CRT → k mod M**, M > k이면 k 직접 복구. M ≤ k이면 `(2·k_bound / M)` 개 candidate brute force.

## 전형적 예

### TetCTF 2021 "Unevaluated"
- order = p·q·r, 각 ~127-bit → order ~381-bit
- k = urandom(32) → **256-bit** (order보다 작음!)
- p, q (큰 두 개) 풀고 r 생략:
  - k mod p: p-adic log (O(1))
  - k mod q: Sage discrete_log in F_p* (수 분)
  - p·q > 2²⁵⁴, k < 2²⁵⁶ → **candidate 최대 4개**

### 일반적 트리거 상황
- AES/기타 대칭 키가 DH secret → 키 size (128/192/256) vs group order size 비교
- ECDSA에서 nonce bound ≪ curve order
- 시간 제한된 타임스탬프가 exponent

## 적용 절차
1. **bit count 비교**: `k.bit_length()` vs `order.bit_length()`
2. **factor 정렬**: p₁ > p₂ > ··· > pₘ
3. **누적 곱으로 커버 최소 factor 수 k′ 찾기**: `p₁·p₂···p_{k′} > 2^{k_bits}` 최초
4. **그 k′개만 DLP 해결**, CRT
5. `candidate_count = k_bound / (p₁···p_{k′})` 이내 brute force (plaintext 검증)

## 주의
- 작은 factor 먼저 쓰면 모듈러스 커버리지가 부족 → 큰 factor 우선
- "k가 256-bit니까 order가 어차피 더 크면 전부 풀어야지?"라고 생각 금지. Partial로 충분할 수 있음.

## 코드 패턴
```python
factors_sorted = sorted(factors, reverse=True)
M = 1
selected = []
for f in factors_sorted:
    selected.append(f)
    M *= f
    if M > k_bound:
        break
# Solve DLP mod each f in selected (skip the rest)
residues = [dlp_mod(f) for f in selected]
x0 = crt(residues, selected)
for i in range(2 * k_bound // M + 2):
    cand = x0 + i*M
    if cand >= k_bound: break
    if verify(cand): return cand
```

## 관련
- `gaussian-int-padic-dlp` — Z[i]/p² DLP에서 이 패턴 적용
- `pohlig-hellman-ecdlp` — smooth order ECDLP (전체 factor 풀기)
