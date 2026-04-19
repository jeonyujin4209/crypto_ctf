---
name: recurrence-jordan-block-no-dlp
description: 선형 recurrence char poly에 중복 인수 (g(x))^k가 있으면 companion 행렬에 nilpotent Jordan block 존재. M^n 작용이 n의 **다항식**(binomial)으로 전개 → 계수 비율로 n 직접 복구, DLP 불필요.
type: attack
---

# Jordan Block in BM Char Poly → Index Recovery Without DLP

## 시나리오

숨겨진 거대 index `n`(e.g. `n ∈ [0, 13^37)`, ~2^137 비트)에서 선형 recurrence의 **연속 구간** 관측:
- 관측: `f(n), f(n+1), ..., f(n+K-1)`
- 초기값: `f(0), ..., f(L-1)` 계산 가능 (공개 수식)
- 과제: `n` 자체를 복구 (matrix power state를 match)

일반적으로 matrix DLP → 거대 group에서 infeasible. BUT:

## 트리거 조건

Berlekamp-Massey로 얻은 char poly `P(x) = X^L - c_1 X^{L-1} - ...` 가 **중복 인수** 포함:
```
P(x) = g_1(x) · g_2(x) · ... · (q(x))^k · ...     (k ≥ 2)
```

이 경우 companion matrix `M`은 `q(M)`-block에서 **nilpotent 구조**를 가진다.

## 왜 Jordan block이 n-polynomial?

Let `N = q(M)` restricted to invariant subspace `V = ker(q(M)^k)`. Then `N^k = 0` on V (minimal poly divides `q^k`). So on V:

```
M^n v  restricted  = ???
```

구체적: `q(x) = x^d + c` 이라면 `x^d ≡ -c + N` on V (N = nilpotent, `N^k = 0`).
쓴 `n = dm + r` (0 ≤ r < d), 그러면 `x^{dm} = (x^d)^m ≡ (-c + N)^m`. N^k = 0이므로 Binomial expansion은 **유한합**(j = 0..k-1):

```
x^{dm} ≡ Σ_{j=0..k-1} C(m, j) (-c)^{m-j} N^j   (mod q(x)^k)
x^n    ≡ x^r · [Σ C(m,j) (-c)^{m-j} N^j]
```

**핵심**: 계수 `A_0 = (-c)^m`, `A_1 = m·(-c)^{m-1}`, `A_2 = C(m,2)·(-c)^{m-2}`, ...
비율 `A_1 / A_0 = m / (-c)` → **m = -c · A_1 / A_0** (field 원소로). 만약 `m < p`면 정수 그대로.

## 알고리즘 (구체적, k=3, q(x)=x^d+c)

1. **BM → char poly P(x)**. Factor. 중복 factor `(x^d + c)^3` 식별.
2. **CRT projector** R(x) s.t. `R ≡ 1 mod (x^d+c)^3`, `R ≡ 0 mod Q(x)` (Q = P / (x^d+c)^3).
   ```python
   g, a, b = xgcd((x^d+c)^3, Q)
   assert g == 1
   R = b * Q    # satisfies R ≡ 1 mod (x^d+c)^3 and R ≡ 0 mod Q
   ```
3. **Project** initial state `s_0` and observed state `s_n`:
   ```python
   s0_V = R(M) · s_0;   sn_V = R(M) · s_n
   ```
4. **Cyclic basis** `{s_0', M s_0', M^2 s_0', ..., M^{dk-1} s_0'}` (dim = d·k 예시 d=3, k=3 → 9).
   계수 `c_0, c_1, ..., c_{dk-1}` s.t. `s_n' = Σ c_j M^j s_0'` (linear system solve).
5. **해석**: `c_j`는 `x^n mod (x^d+c)^k`의 basis 표현. `N = x^d + c` 전개:
   - `N = x^d + c`, `N^2 = x^{2d} + 2c·x^d + c^2`, ...
   - `x^r · [A_0 + A_1 N + A_2 N^2]` 를 `{1, x, ..., x^{dk-1}}` basis에서 전개하면, non-zero 위치는 `{r, r+d, r+2d, ...}` (k개 위치).
6. **Extract** `A_0, A_1, A_2` (from {r, r+d, r+2d}위치 값), 단 $N^j$ 전개식 풀기:
   - 관측 `c_r = A_0 + c·A_1 + c^2·A_2`
   - `c_{r+d} = A_1 + 2c·A_2`
   - `c_{r+2d} = A_2`
   - 이를 역산: `A_2 = c_{r+2d}`, `A_1 = c_{r+d} - 2c·A_2`, `A_0 = c_r - c·A_1 - c^2·A_2`
7. **Recover m, r**:
   - `r = argmin { r : c_{r}, c_{r+d}, c_{r+2d} 모두 nonzero }` (0 ≤ r < d)
   - `m = -c · A_1 / A_0`  as field element; cast to int (valid if m < p)
   - **검증**: `A_0 == (-c)^m`, `A_2 == C(m,2)·A_0 / c^2`
8. **n = d·m + r**. Done.

## 왜 DLP 피할 수 있나

Jordan block은 eigenvalue가 반복 → `M^n` 의 한 블럭에서 지수적 growth 대신 **다항식 growth** (`m`, `C(m,2)`, ...). 이 polynomial-in-n 구조가 log 없이 n을 **선형/2차 방정식**으로 풀리게 한다.

반대로 diagonal (단순 eigenvalue) block에서는 `λ^n` → DLP 필요.

## 적용 가능 vs 불가

**가능:**
- BM 결과 char poly에 **중복 인수** 존재 (multiplicity ≥ 2)
- 초기/관측 state 모두 계산 가능
- `n < p` (대개 CTF setting 만족; 아니면 mod p만 복구)

**불가:**
- Char poly가 **square-free**: 모든 invariant subspace가 diagonal → scalar DLP에 의존
- 관측된 state가 Jordan subspace에 미포함 (projector 결과 0)
- 초기 state `s_0'`이 cyclic 생성자 아님 (rank 체크 필수)

## 관련 체크리스트

```python
from sage.matrix.berlekamp_massey import berlekamp_massey
Pf = berlekamp_massey(seq)
fac = Pf.factor()
# 중복 factor 찾기
repeated = [(f, m) for f, m in fac if m >= 2]
if repeated:
    print(f"Jordan-block candidate: {repeated[0]}")
    # 위 algorithm 진행
else:
    print("No repeated factor → scalar DLP or BSGS 필요")
```

## 출처

- CryptoHack CTF Archive 2022: Functional (ICC Athens)
  - `F = GF(2^142 - 111)`, L=20 linear recurrence `f` with unknown COEFFS, 500 consecutive
    values observed at ITERS+0..ITERS+499, ITERS ~ 13^37 (≈2^137)
  - BM → char poly factors: (quad)(quad)(x^3 + 31337)^**3**(septic)
  - **중복 인수** (x^3+31337)^3 → Jordan block of dim 9
  - ITERS = 79120327624133200239720213852419346424887 복구, DLP 없이 ~0.1 s
  - 검증: 500/500 stage1 value match

- 일반 배경: Fiduccia/Kitamasa polynomial power 계산 + CRT + companion matrix Jordan form
