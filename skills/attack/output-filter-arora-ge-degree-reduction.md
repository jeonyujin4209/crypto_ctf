---
name: output-filter-arora-ge-degree-reduction
description: PRF output이 {0,1}이고 각 value에 대응하는 poly annihilator 차수가 다르면, 낮은 차수 쪽만 필터해 Arora-Ge. 전체 쿼리 cubic→filter→quadratic으로 모노미얼 수 22×감소
type: attack
---

# Filter by Output Class to Reduce Arora-Ge Degree

## 유형
Output이 `{0, 1}` (또는 small set) 형태의 함수 `f(x) = g(<k, h(x)>)`:
- Output=A → secret에 대한 **높은 차수** 다항식 annihilator (e.g. cubic)
- Output=B → **낮은 차수** annihilator (e.g. quadratic)

이 때 **output=B 샘플만 수집**해서 Arora-Ge linearize → 훨씬 적은 monomial로 해결.

## Trigger 패턴
```
f(x) = (inner_product(k, h(x)) mod q) mod p  # p < q, p small
```
예: `q=5, p=2`. Output=0 ⇔ `<k,h> mod 5 ∈ {0, 2, 4}` (cubic annihilator `y(y-2)(y-4)`), output=1 ⇔ `{1, 3}` (quadratic `(y-1)(y-3)`).

## 왜 차수가 중요한가
Arora-Ge monomial count over `n` variables:
- Degree 2: `C(n+2, 2) + n + 1 ≈ n²/2 + O(n)`
- Degree 3: `C(n+3, 3) ≈ n³/6`
- Degree 4: `C(n+4, 4) ≈ n⁴/24`

n=64 기준: deg2 = 2145, deg3 = 46,000+, deg4 = ~800k. **한 차수만 올라가도 20~40배 폭증**.

Filter by output → 가장 낮은 차수로 환원.

## 구현 (Gen 3 예)

```python
# Monomial layout: k_i*k_j (i<=j) [quad_n=n(n+1)/2] + k_i [n] + const [1]
def build_row_out1(h):
    """(y-1)(y-3) = y² - 4y + 3 = y² + y + 3 (mod 5), y = <k,h>."""
    row = np.zeros(TOTAL, dtype=np.int64)
    # y² = Σ k_i k_j h_i h_j
    for i in range(n):
        row[quad_idx(i, i)] = (h[i] * h[i]) % 5
        for j in range(i+1, n):
            row[quad_idx(i, j)] = (2 * h[i] * h[j]) % 5
    # y term: Σ k_i h_i
    for i in range(n):
        row[lin_off + i] = h[i] % 5
    row[-1] = 3  # const
    return row % 5

# Collect output=1 samples only
rows = []
for x in range(max_queries):
    out = query(x)
    if out == 1:
        rows.append(build_row_out1(hashed(x)))
        if len(rows) >= TOTAL + 20:  # overdetermine a bit
            break
# Solve over GF(5)
solve_mod5(A=rows[:,:-1], b=(-rows[:,-1]) % 5)
```

## 쿼리 예산
`P(output=B) = r` (예: 2/5 for p=5,q=2). 필요 샘플 수 = M (monomial count).
Total queries ≈ `M / r`.

n=64, M=2145, r=2/5: 5500+ queries. 실전 8000이면 output=1 count ~3200개 → TOTAL+안전마진.

## Gaussian elimination over GF(q)
- numpy 기반 vectorized: 2145 × 2145 matrix 약 **60초** (Python 루프 + numpy ops)
- Sage GF(5) matrix RREF도 비슷 (galois 패키지도 유사)
- Faster: C-level SymPy, SageMath linbox backend

시간 budget 촉박하면 **sage docker 호출**로 RREF 위임 (`matrix(GF(5), ...).rref()`) 권장.

## 적용 가능
- Output이 partition 가능하고 각 partition이 서로 다른 차수 annihilator일 때
- `(a mod q) mod p`, `a mod q ∈ {...}` 등 piecewise-defined outputs
- Generally any `f(x) → {A_1, ..., A_k}` where `A_i` 마다 `deg_i`-degree polynomial이 0

## 적용 불가
- 모든 output value가 동일한 최저 차수 annihilator (필터해도 같은 복잡도)
- `P(low-degree output)` 너무 낮아 쿼리 예산 초과

## 관련 skills
- `arora-ge-binary-lwe` — 표준 Arora-Ge linearization (binary/bounded error)
- 이 skill은 그 확장: 비-linear output function에서 output-conditional filtering

## 출처
- CryptoHack CTF Archive 2022: Dark Arts (CODEGATE 2022) Generator3
  - `f(x) = (<k,h> mod 5) mod 2`, k ∈ {0,1,2,3}^64, h = base-5 sha256 digits
  - Output=1 → `(y-1)(y-3)≡0`, quadratic in 64 vars, 2145 monomials over GF(5)
  - 8000 queries → 3200 output=1 rows → Gauss eliminate → k 복구 (per-entry `%5` check)
  - 만약 cubic(output=0) 썼다면 46k monomial → 100k+ queries 필요 → alarm 초과
