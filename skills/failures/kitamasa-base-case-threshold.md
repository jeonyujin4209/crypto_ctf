---
name: kitamasa-base-case-threshold
description: Kitamasa order L = base-case **threshold** T (`n < T → base`), NOT recurrence의 max-shift. Off-by-one이면 sanity check가 서로 같은 버그로 "match=True"를 줘서 속기 쉬움.
type: failure
---

# Kitamasa Off-by-One: Use Base Threshold, Not Max-Shift

## 현상

Recurrence 정의:
```python
def seq(n):
    if n < T:           # base case
        return base(n)
    return Σ c_k · seq(n - k)    # recurrence, with max shift ≤ M  (M ≤ T 보통)
```

Kitamasa 쓸 때 흔한 실수: `L = M` (max-shift)로 설정. 이 경우:
- Char poly degree = M
- Base vector `[seq(0), seq(1), ..., seq(M-1)]`
- 결과: `seq(N) = Σ r_k · seq(k)` for k=0..M-1, where `r(X) = X^N mod P(X)`

**버그**: 이 공식은 `seq(n) = Σ c_k seq(n-k)` 가 **n ≥ M** 부터 성립한다고 가정. 하지만 실제 recurrence는 **n ≥ T** 부터만 성립. `M ≤ T`이면, `seq(M), ..., seq(T-1)`는 **base case** 값인데 kitamasa는 recurrence로 계산한 값으로 가정 → 오류.

## 예 (Functional, ICC Athens 2022)

```python
def j(n):
    if n < 10^4:                                      # T = 10000
        return F(sum(S3[d] for d in ZZ(n).digits(1337)))
    return [α_i]_{i=0..99}.dot([j(n-9900-i) for i])   # max shift = 9999
```

Max shift = 9999 (M = 9999). Base threshold = 10000 (T).
- **잘못된** 설정: L = 9999, base = j(0..9998), P(X) = X^9999 - Σ α_i X^{99-i}
  → j(9999) = Σ α_i · j(99 - i) (recurrence 로 계산한 값). 실제 j(9999) = base case 값 = S3[640] + S3[7]. **불일치**.
- **올바른** 설정: L = 10000, base = j(0..9999), P(X) = X^10000 - Σ α_i X^{100-i}

## 함정: Sanity check "match=True" ≠ 정답

전형적 버그: Kitamasa 결과와 **자체 구현 forward simulation** 비교. 둘 다 똑같이 "recurrence at n=9999"를 가정하면 둘 다 틀린 값 내는데 서로 일치 → **match=True**.

```python
# 버그 있는 sanity check
j_full = [base(k) for k in range(M)]   # L=M 버전, k=0..M-1만 base
for n in range(M, N_test + 1):
    j_full.append(Σ α_i · j_full[...])  # recurrence starts at n=M, but should start at n=T
# Kitamasa(N_test)도 M 기반 → 같은 오류
```

## 체크리스트

1. **Base case threshold T 확인**: `if n < T` 문 읽고 정확한 T 추출. T = 10^4 vs 10000 vs 9999 구분.
2. **Recurrence max-shift M 확인**: `seq(n - k)` 최대 k 값.
3. **Kitamasa order L = T** (base values j(0..T-1)로 구성). NOT M.
4. **Char poly degree = T**, 계수 placement: `c_k = α_{k-M1}` for `M1 ≤ k ≤ M`, else 0, where M1 is min shift.
5. **Sanity check**: 두 독립 경로로 검증 — 예를 들어, 서로 다른 N에서 Kitamasa 결과 vs 작은 N까지 naive forward sim (반드시 base=True를 올바르게 적용한 naive).

## 디버깅 tip

실제 CTF 풀이 중 decrypt 실패 → 오류 위치 추적:
- ITERS 검증: 500 연속 값 중 몇 개가 match? 모두 match면 ITERS 정답.
- S3 / intermediate: 독립 검증 어려움 — 작은 N=10000 직접 계산 vs Kitamasa (올바른 L로!).
- j(ITERS) 자체: sanity를 올바른 L로 다시 쓰기.

**AES-ECB decrypt로 "raw garbage bytes + unpad fail"** → 키가 완전히 틀림. 일부 비트 오류 아니라 전체 엉망. 이건 **입력 단계** 오류 (j or ITERS 자체 오류), 암호화 코드 문제 아님.

## 일반화

```
"n < T: base, n ≥ T: Σ c_k · seq(n-k) with max k = M"
→ Kitamasa L = T (not M). Char poly = X^T - Σ c_k X^{T-k}.
```

Edge: `T = M`이면 (recurrence가 정확히 처음 가능한 index에서 시작) off-by-one 없음. `T > M`이면 off-by-one 위험.

## 출처

- CryptoHack CTF Archive 2022: Functional (ICC Athens)
  - j(n): T=10^4, M=9999. L=9999 설정 시 decrypt AES garbage, L=10000 설정 시 flag recover.
  - 자체 구현 naive forward에서도 base=j(0..9998) 넣고 n=9999부터 recurrence로 append → **match=True**로 속음.
  - 수정: base=j(0..9999), char poly degree 10000, L=10000.
  - Flag: `ICC{N0w_y0u_4re_a_mast3r_0f_t3h_l1n34r_r3curr3nc3s!}`
