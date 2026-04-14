---
name: matrix-dh-repeated-root-local-ring
description: Matrix DH에서 min_poly가 중복근 → local ring trick으로 DLP 없이 SECRET = λ·b/a 즉시 복구. DLP 시도 전 squarefree 검사 필수
type: skill
---

# Matrix DH with Repeated Root → Local Ring Trick Gives SECRET Directly

## 유형
Matrix Diffie-Hellman / Matrix DLP where `H = G^SECRET` over GF(p),
with `G` an n×n matrix. The **standard** approach (factor min_poly,
solve eigenvalue-wise DLP, CRT) can fail catastrophically if ord(G)
contains a large prime factor — but the problem may still be trivially
solvable if `min_poly(G)` has a **repeated** linear factor.

## Trigger 패턴
Matrix DH / matrix DLP 문제를 받으면 **DLP 접근 *전에*** 항상 squarefree 검사:
- `G ∈ GL_n(GF(p))`, `H = G^SECRET` 주어짐
- 목표: `SECRET`을 정수로 복구 (AES 키가 `str(SECRET)`에서 유도되는 경우 등)
- p가 크고 `p-1`에 큰 prime factor가 있어서 일반 DLP가 hopeless해 보임
- **즉시 체크**: `gcd(min_poly(G), min_poly'(G))` — 이게 nontrivial하면 잭팟

## 왜 못 풀었나 (A)

### 삽질 1: 모든 eigenvalue 찾고 각 order 분석
CryptoHack *The Matrix Reloaded* (N=30, 512-bit p).

1. Krylov로 min_poly 구함 (degree 30, 모두 GF(p)에 뿌리)
2. Cantor-Zassenhaus로 30개 root 추출
3. `p-1 = 2·5·71·100741·3008773·p1·p2` (p1: 101-bit prime, p2: 365-bit prime)
4. 모든 eigenvalue가 order에 `p2`를 포함 → smooth part는 고작 48-bit
5. "48-bit mod 정보로는 512-bit SECRET 못 복구..." → 막힘

이 시점에서 "challenge가 solvable이어야 하니 뭔가 놓친 거다" 싶었는데, 계속 eigenvalue DLP에만 매달림.

### 삽질 2: G^(p-1) ≠ I 발견
`G^(p-1) == I` 기대했는데 아님 → "뭔가 이상하다" 감지.

*여기서* squarefree 검사를 했어야 했는데, 대신 "min_poly가 잘못 계산됐나?" 하고 Krylov 다시 돌림.

### 삽질 3: 중복 근 발견
Cantor-Zassenhaus 결과에서 `Counter(roots)` 돌려보니 30개 중 29개 unique + 1개 중복 → 이제야 깨달음.

**이 체크를 *맨 처음에* 했어야 함.** DDF 돌리기 전에 `gcd(f, f')`만 보면 끝.

## 어떻게 해결했나 (B)

### 핵심 수학
Min_poly가 `(x - λ)²`를 factor로 가지면, 국소환
`R = GF(p)[x]/(x - λ)²`에서 작업. Binomial expansion:

```
x^k = (λ + (x - λ))^k
    = λ^k + C(k,1)·λ^(k-1)·(x-λ) + C(k,2)·λ^(k-2)·(x-λ)² + ...
```

`(x - λ)²` 법에서 j ≥ 2 항은 전부 0 → 오직 두 항만 살아남음:

```
x^k ≡ λ^k + k·λ^(k-1)·(x - λ)  (mod (x - λ)²)
```

### Recovery 공식
`H = G^SECRET`에 대응하는 polynomial `c(x)` (Krylov target-poly)를 구하고, `(x - λ)²`로 reduce:

```
c(x) mod (x - λ)² = a + b·(x - λ)
  where  a = λ^SECRET
         b = SECRET · λ^(SECRET - 1)
```

따라서:
```
SECRET ≡ λ · b / a   (mod p)
```

**DLP 완전히 필요 없음.** Modular inverse 하나로 끝. p보다 작은 SECRET이면 정확한 값 복구.

### 코드 스켈레톤
```python
# 1. Krylov로 min_poly (monic, ascending 계수) + target poly c 구하기
#    d: G^N v = sum d_i G^i v  →  min_poly = x^N - sum d_i x^i
#    c: w = sum c_i G^i v       →  target polynomial for H

# 2. squarefree 검사
min_poly_deriv = [(i * min_poly[i]) % p for i in range(1, len(min_poly))]
g = poly_gcd(min_poly, min_poly_deriv)
assert len(g) == 2, "no repeated linear factor"   # g = (x - λ), monic

lam = (-g[0]) % p   # g = [-λ, 1]

# 3. c(x) mod (x - λ)²
sq = [(lam * lam) % p, (-2 * lam) % p, 1]
_, c_red = poly_divmod(c, sq)
while len(c_red) < 2:
    c_red.append(0)
c0, c1 = c_red[0], c_red[1]

# 4. (x - λ) basis로 환산
a = (c0 + c1 * lam) % p
b = c1

# 5. SECRET = λ · b / a (mod p)
SECRET = (lam * b % p) * pow(a, -1, p) % p
assert pow(lam, SECRET, p) == a   # 검증
```

### 검증 체크리스트
- `pow(lam, SECRET, p) == a` (필수 sanity)
- derived AES key로 flag 복호화 → padding 정상

## 일반화
- **Char 0 / odd char**: 공식 그대로 쓸 수 있음
- **Char 2**: 공식이 망가짐 (`k·λ^(k-1)`가 `k mod 2`만 남김). 이 경우엔 다른 트릭 필요
  (CryptoHack *The Matrix Revolutions*가 이 경우인데, 거기선 min_poly가 squarefree라 애초에 이 트릭이 안 먹음)
- **중복도 ≥ 3**: `(x - λ)^m`, m ≥ 3일 땐 더 많은 Taylor 계수가 살아남음.
  `C(k, j)·λ^(k-j)` for `j = 0..m-1`. j=2 계수에서 `k(k-1)/2` 회수 가능하므로
  quadratic equation 풀면 됨. 더 높은 m은 더 많은 bit 정보 추출 가능.
- **중복 factor가 비-선형** (예: `f(x)²` with `deg f > 1`): 같은 원리지만 local ring이
  `GF(p^deg f)[ε]/ε²` 구조. α = root(f) in GF(p^deg f), `SECRET = α·b/a`를
  extension field에서 계산 후 `p`에 사영

## Trigger 요약 (skill 사용 체크리스트)
Matrix DH / matrix DLP 문제를 보면:
1. ✅ Krylov로 min_poly 구하기
2. ✅ **`gcd(min_poly, min_poly') != 1` 검사** ← 이게 이 스킬의 핵심
3. ✅ Trivial하지 않으면: 중복 근 λ 추출 → local ring 공식으로 SECRET 즉시 복구
4. ❌ Squarefree면: 이 스킬 안 먹음. 통상적인 eigenvalue DLP / CRT 루트

## 출처
- CryptoHack: The Matrix Reloaded (100pts, Diffie-Hellman / Misc)
  - 512-bit p, 30×30 matrix, SECRET ∈ [0, p-1)
  - min_poly가 29개 distinct linear + 1개 중복 (총 30개 뿌리이되 squarefree 아님)
  - `SECRET = λ · b / a (mod p)`로 단 한 번의 modular inverse로 해결

## 메모
- "Matrix DLP 문제는 DLP다"라는 고정관념이 삽질의 원인. **Matrix DH는 다항식 링 문제**.
- squarefree 검사는 O(n²) 무료 연산. **항상 먼저** 해야 함.
- 이 트릭은 원래 `p`-adic log / formal group log의 local version — Smart attack
  (supersingular ECDLP)과 수학적으로 같은 뿌리 (nilpotent 방향의 log는 자명함)
