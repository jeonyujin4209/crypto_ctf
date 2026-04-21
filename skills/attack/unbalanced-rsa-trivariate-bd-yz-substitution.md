---
name: unbalanced-rsa-trivariate-bd-yz-substitution
description: Unbalanced RSA (p=N^β, β<0.5) with small d: 2-variable 큐빅 reduction (q=N/p 치환 후 p 곱) 대신 **3-variable** Boneh-Durfee polynomial `1 + x(N+1-y-z)` 쓰고 `poly_sub(y*z, N)`로 y·z를 quotient ring에서 N으로 치환. 불균형 심할수록 공격이 쉬워짐.
type: attack
---

# Unbalanced RSA with Small d: Trivariate Boneh-Durfee + y·z = N Substitution

## 문제 유형

RSA `(N, e, c)`, d 비밀. 조건:
- `N = p·q`, unbalanced (예: p는 256-bit, q는 768-bit, N은 1024-bit)
- `d`가 작음 (예: 300-bit, 즉 N^0.293)
- 표준 Boneh-Durfee 경계 δ < 0.292는 **balanced** primes 가정. Unbalanced에선 다른 공격 필요

**플래그의 힌트**: `unbalanced primes only make things worse` — 불균형이 공격을 **쉽게** 만듬.

ICC Athens 2022 "Unbalanced"가 prototype.

## 왜 기본 공격들이 실패하는가

### Wiener / Blömer-May CF variants

`|e/A - k/d| ≈ k·s/(Nd)` with `s = p+q ≈ q ≈ N^{1-β}`. Unbalanced에선 `s`가 너무 커서 오차 ~2^{-256} (필요: 2^{-601}). 확인됨 실측.

### Boneh-Durfee with `y = p+q ≈ q`

BD polynomial `f(x, y) = 1 + x(N+1-y)`, Y = N^{1-β} ≈ N^{0.75}. Bound `X·Y² < e^{3/2}` 실패: δ + 2(1-β) < 3/2 필요, β=0.25면 δ < -0.5 (불가능).

### 2-variable 큐빅 reduction (흔한 함정)

`q = N/p` 대입 후 양변에 p 곱:
$$
k(p-1)(N-p) + p \equiv 0 \pmod e
$$
전개: `-xy² + (N+1)xy - Nx + y ≡ 0 mod e`, x=k, y=p. Y = N^β ≈ N^{0.25} (훨씬 작음!).

Newton polygon: triangle (0,1), (1,0), (1,2). Jochemsz-May basic asymptotic bound:
$$
\tfrac{2}{3} \log X + \log Y < \tfrac{4}{9} \log e
$$
δ 관점: δ < 2/3 - 3β/2. β=0.25: δ < 0.292 — **balanced BD와 같음, β와 무관**. 우리 d=N^0.293 경계 위. 실패.

## 올바른 공격: Trivariate + `poly_sub(y*z, N)`

### 핵심 아이디어

`y·z = N`(exact integer relation)을 **polynomial ring 안에서** 치환. bivariate `y=p`로 수동 축소하는 것과 **수학적으로 동일한 정보**이지만 **lattice 구조가 완전히 다름** — y·z = N substitution을 shift polynomial을 **형성한 후** 적용하면 monomial 분포가 균형있어져 Coppersmith bound가 느슨해짐.

### Polynomial

$$
f(x, y, z) = 1 + x(N+1 - y - z) \pmod e
$$

`(x, y, z) = (k, p, q)`가 mod e root. X=2^300, Y=2^256, Z=2^768.

### Shift polynomials (Boneh-Durfee 구조)

```
for k in range(m):
    for i in range(1, m-k+1):
        for b in range(2):
            g = e^(m-k) * x^i * z^b * f^k          # x-shifts
            g = poly_sub(g, y*z, N)                 # ← 핵심!
            
for k in range(m+1):
    for j in range(t+1):
        h = e^(m-k) * y^j * f^k                     # y-shifts (upper envelope)
        h = poly_sub(h, y*z, N)
```

### `poly_sub` 구현 (Sage)

```python
def poly_sub(f, x, y):
    """Replace x with y in polynomial f via quotient ring."""
    Q = f.parent().quotient(x - y)
    return Q(f).lift()
```

`poly_sub(f, y*z, N)`: polynomial ring에서 `y*z - N`의 ideal로 나눈 quotient로 올려 뒤 lift. 결과: `y^α · z^β` with α, β ≥ 1 이 `N^{min(α,β)} · y^{α-min} · z^{β-min}`로 치환 (mixed monomial 제거, pure y^power 또는 z^power만 남음).

### Lattice 구성

Sage `Sequence.coefficients_monomials()` + diagonal scaling `W = diag(bound_monomial_i)`. LLL on `B*W`, 후 un-scale.

```python
B, monomials = polys.coefficients_monomials()
W = diagonal_matrix([mon(*bounds) for mon in monomials])
B = (B*W).dense_matrix().LLL() / W
H = list(B * monomials)
```

### Root 추출 (Gröbner basis)

LLL rows은 polynomial 여러 개. Reversed subset size로 Gröbner basis 시도 — univariate polynomial in y(=p)가 나오면 roots 찾음:

```python
for i in reversed(range(len(H))):
    try:
        gb = Ideal(H[:i]).groebner_basis()
        roots = gb[0].univariate_polynomial().roots()
        p = max(roots)[0]
        q = N // p
        if p * q == N: break
    except:
        continue
```

## 구체 파라미터 (ICC Athens "Unbalanced")

- `m=5, t=5, a=0`, bounds `(2^300, 2^256, 2^768)`
- Lattice 66×66, LLL 21초
- Ideal subset size 46에서 p 복구 성공

## 왜 trivariate + poly_sub가 bivariate 큐빅보다 강한가

Bivariate 큐빅: **2-variable** Newton polygon 작고 삼각형. asymptotic bound `(2/3)·δ + β < 4/9`가 β와 무관하게 δ < 0.292로 수렴.

Trivariate + poly_sub: **3-variable** 로 시작하지만 `y·z = N` 치환으로 effective 2-variable. 하지만 **y^power, z^power를 대칭적으로 커버하는 shift set** (x-shift에 `z^b for b ∈ {0, 1}`, y-shift에 `y^j for j ∈ [0, t]`)을 쓰므로 y-direction과 z-direction의 contribution이 β에 따라 달라짐. Unbalanced일수록 z가 커서 포함되는 **N의 거듭제곱 (from y·z = N substitution)이 lattice determinant에 기여**, 바운드가 β 따라 완화됨.

구체적으로: Unbalanced(β<0.5)일 때 기술이 강력해지는 이유 = `N^{yz-terms}` factor가 x-shifts에서 덧붙어 modulus의 "effective power"를 늘려줌. 결과: **d < N^{small function of β}** 공격 성립.

## 일반화

이 기법은 다음에 적용:

1. **모든 unbalanced RSA with small d** — 플래그가 맞음, "불균형이 오히려 공격 쉽게 함"
2. **CRT-RSA with small d_p, d_q** — 유사 치환 trick
3. **Multi-prime RSA** `N = p_1·p_2·p_3` — quotient ring에 다변수 constraint 여러 개 넣기

## 실수 패턴 (내가 빠진 함정)

1. **Bivariate 큐빅만 시도**: q=N/p로 2-variable로 환원한 후 붙잡힘. 3-variable 유지하면서 제약만 치환하는 선택지 놓침
2. **CF/Wiener variants**: 불균형에서 error ~2^{-256}, hopelessly too big. 시간 낭비
3. **Basic BD (Y=p+q)**: unbalanced에서 Y 너무 큼. 시도조차 불필요
4. **Asymptotic bound 계산 후 경계면 기회 포기**: 사실 bivariate 큐빅은 margin 0이지만 **trivariate는 margin 큼**. 정확한 공격 선택이 중요 >> asymptotic 분석

## 출처

- CryptoHack CTF Archive 2022 ICC Athens: Unbalanced (maple3142 writeup)
- Gist: https://gist.github.com/maple3142/0bb20789d7372b7e0e822d1b91ca7867
- Original Boneh-Durfee: Asiacrypt 1999 "Cryptanalysis of RSA with Private Key d Less Than N^0.292"
