---
name: nested-lcg-rsa-base-q-layered-recovery
description: User-controlled one of three nested LCGs encoding primes as base-q digits. Inject counter into low digit via (a=1,x=1,b=1) → extract roll indices from n mod q, LCG2 from n mod q², then Coppersmith
type: attack
---

# Nested-LCG RSA with User-Controlled Layer: Layered Base-q Recovery

## 문제 유형

RSA 변형: prime을 3-layer nested LCG로 생성:
```python
p = L3.fetch() * q^2 + L2.fetch() * q + L1.fetch()   # 각 L_i ∈ [0, q)
```
$q$ 공개, 342-bit 정도. 공격자는 **LCG1의 (a, x, b)만 제어**. LCG2, LCG3는 서버 랜덤.

$p$가 $\approx q^3$-bit (예: 1026-bit, 2048-bit RSA). 정확히 **base-$q$ 3자리수**.

`isPrime` filter 때문에 대부분의 roll 실패. 8개 prime 모을 때까지 ~$700 \times 8 = 5600$ roll 소비.

여러 RSA 모듈러스 $n_1, \ldots, n_4$ (각 2 primes 곱)을 **모두 factor**하는 것이 목표.

WACON 2022 "RSA Secret Sharing" (rkm0959, 2-out-of-3 RSA SSS from MemeCrypt) 프로토타입.

## 핵심 아이디어 (4-Step Layered Recovery)

### Step 1: LCG1 = **(a=1, x=1, b=1)** → Roll index를 base-$q$ 최하위자리에 주입

$L_{1,i} = 1 + i$ (roll index). Roll index $< q$이면 no wrap.

각 prime $p$의 base-$q$ 최하위자리 = roll index + 1 (= known).

### Step 2: $n \bmod q$ 에서 roll index 복구

$n_k = p_a \cdot p_b$에서 $p_a \equiv 1 + r_a \pmod q$, $p_b \equiv 1 + r_b \pmod q$이므로:

$$
n_k \bmod q = (1 + r_a)(1 + r_b)
$$

$(1+r_a)(1+r_b) \le 10000^2 \ll q$이므로 **modular reduction 없음**. $n_k \bmod q$는 작은 정수 — 소인수분해해서 $(r_a, r_b)$ 복구.

여러 factorization 후보 있으면 **monotone 순서** 조건 ($r_0 < r_1 < \cdots < r_7$)로 disambiguate.

### Step 3: $n \bmod q^2$ 에서 LCG2 parameter 복구

$n_k \bmod q^2 = L_1^{(a)} L_1^{(b)} + q \cdot (L_2^{(a)} L_1^{(b)} + L_2^{(b)} L_1^{(a)}) \bmod q^2$.

$A_k = (1+r_a)(1+r_b)$ 뺀 후 $q$로 나누면:
$$
B_k = L_2^{(r_a)} \cdot (1+r_b) + L_2^{(r_b)} \cdot (1+r_a) \pmod q
$$

LCG2 recurrence $L_{2,i} = \alpha \cdot a_2^i + \beta$ (fixed-point 변환) 대입:
$$
B_k = \alpha \cdot f_k(a_2) + \beta \cdot d_k \pmod q
$$
where $f_k(x) = (1+r_b) x^{r_a} + (1+r_a) x^{r_b}$, $d_k = r_a + r_b + 2$.

**4 equations, 3 unknowns $(\alpha, \beta, a_2)$**. Over-determined → 3×3 augmented matrix det = 0:

$$
P(x) = f_0(x)(d_1 B_2 - d_2 B_1) + f_1(x)(d_2 B_0 - d_0 B_2) + f_2(x)(d_0 B_1 - d_1 B_0)
$$

6-term sparse polynomial in $x = a_2$, degree $\le \max_i r_i \approx 5000$. `P.roots(ring=GF(q))`로 근 찾고 4번째 식으로 검증.

**중요**: 두 다른 triple (e.g., $\{0,1,2\}$와 $\{0,1,3\}$)로 $P_1, P_2$ 생성 후 $\gcd$ 취해 spurious root 줄이기.

### Step 4: Known $(L_1, L_2)$ → Coppersmith small_roots

LCG2 복구 완료 후 각 prime의 $L_2$ 계산. 이제 각 $p$에 대해 **2/3 자리수 known** ($p \bmod q^2$):

$$
p = q^2 \cdot k + (L_2 \cdot q + L_1), \quad k = L_3 < q
$$

$q^2 \approx N^{1/3} > N^{1/4}$이므로 Coppersmith known-LSB:
```python
f = y + M * inverse_mod(q^2, N)    # M = L_2*q + L_1
f.small_roots(X=int(q), beta=0.5, epsilon=0.02)
```

## 왜 (a=1, x=1, b=1)인가

- $a=1, b=0$ (constant $L_1 = x$): $n \bmod q = x^2$ — 1 equation only, 정보 부족
- $a=1, b=1$ (counter): **$n \bmod q$가 unique index pair 식별자** — 4 moduli × 2 primes = 8 distinct indices 복구 가능
- $x=1$ (initial = 1): 맨 첫 roll이 index 0이 아닌 1에서 시작 (구현 세부, 큰 차이 없음)

## 복잡도

- PoW (26-bit): ~67M SHA256, Python pure ~36s
- Step 2 (factor small ints): 즉시
- Step 3 (polynomial roots mod $q$ of degree ~5000): Sage `.roots()`로 ~10–90s per candidate
- Step 4 (Coppersmith x4): ~5–10s each

전체 live solve: **~80s** (75s attack + PoW amortized).

## 적용 가능 조건

- Nested multi-layer LCG/PRG 구조의 RSA prime 생성
- 최소 1개 layer는 공격자 제어
- Base representation에서 각 layer가 **정확히 한 자리**에 대응
- 최소 4개 공격 모듈러스 (3 params × 1 개별 = 3 unknowns + 1 over-determined check)

## 주의

- Coppersmith `beta=0.5`: p가 $\approx N^{1/2}$일 때. Non-balanced RSA면 조정
- Sparse polynomial degree가 너무 높으면 ($r > 10^4$) root-finding 불가능 — LCG1을 `(a=1,x,b=0)` 같은 constant로 fallback 시도 (but 그러면 Step 2 정보 부족)
- LCG2 `a_2 = 1` edge case (prob $1/q$): formula 달라짐. 무시 가능

## 출처

- CryptoHack CTF Archive 2022 WACON: RSA Secret Sharing (rkm0959 contributed, MemeCrypt 2022)
- Key insight: 최하위 digit에 counter 주입 → 상위 digit LCG를 다항식 시스템으로 환원
