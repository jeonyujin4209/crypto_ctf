---
name: rlwe-reducible-modulus-cyclotomic-crt
description: Ring-LWE 변형이 reducible modulus polynomial (예: x^n - 1 대신 x^n + 1)을 쓰면, Z[x] 상의 cyclotomic factor Phi_d(x) 로 분해 후 각 component에서 작은 격자 공격으로 (s mod Phi_d, e mod Phi_d) 복구 → CRT로 s, e 재구성
type: attack
---

# Reducible-Modulus Ring-LWE: Cyclotomic CRT Attack

## 유형
Ring-LWE based scheme (Lyubashevsky/GLP signatures, Regev encryption variant) where the ring R = Z[x]/(f(x)) uses a **reducible** f(x) such as `x^n - 1` for composite n, or any f = product of cyclotomics.

## Trigger 패턴
- Public key/ciphertext lives in `R_q = F_q[x]/(f(x))` with `f(x) = x^n - 1` and n composite (like 420 = 4·3·5·7)
- Standard secure RLWE uses `x^n + 1` for n a power of 2 (= Phi_{2n}(x), irreducible)
- If you see `phi = x**n - 1` with n composite → **reducible** → factor via Phi_d for d | n
- Secret/error are bounded (binary `{-1,0,1}`, sparse, Gaussian with small sigma)

## 왜 못 풀었나 (실패 시도)

### 시도 1: 직접 격자 공격 (dim 2n+1)
n=420, q≈2^23, ternary secret. uSVP gap ≈ q^(1/2) / sqrt(2n*sigma^2) ≈ 858. Hermite factor needed `gap^(1/(2n+1))` ≈ 1.008 → BKZ-100+ in dim 841. Not feasible in CTF time budget (would need hours).

### 시도 2: ψ_N projection으로 ψ_N(s) 복구 후 합치기
For N | n, ring hom R → F_q[x]/(x^N - 1) gives smaller LWE recovering ψ_N(s)_j = sum_{i ≡ j (mod N)} s_i. Sounds promising.

**문제**: 모든 proper N | n 의 ψ_N 합쳐도 char k coprime to n 인 Fourier component 못 잡음 (kernel dim φ(n) = 96). 결국 ψ_n (=identity) 문제 본질로 돌아옴. **Premature claim of reduction**.

## 어떻게 해결했나

### 핵심 통찰: cyclotomic factorization in Z[x]
`x^n - 1 = prod_{d | n} Phi_d(x)` over **Z[x]** (not just F_q!). Each Phi_d has small Z-coefficients.

For ternary `s ∈ Z[x]/(x^n - 1)` (deg < n), reduce mod each Phi_d:
- `s mod Phi_d` is a Z-polynomial of degree < φ(d).
- **Coefficients stay small** (typically `<= 30` for n=420 even at d=420 where φ(420)=96).

이 fact 가 핵심: small-coef secret이 **각 cyclotomic factor 에서도 small-coef** 으로 유지됨.

### 알고리즘
```
1. For each d | n:
   - Compute a_d = a mod Phi_d, t_d = t mod Phi_d (in F_q[x]/Phi_d).
   - Build LWE matrix M_a (multiplication by a_d in F_q[x]/Phi_d, dim = phi(d) x phi(d)).
   - Construct lattice (dim = 2*phi(d) + 1, Kannan embedding):
       [ I_{phi(d)}        -M_a^T          0 ]
       [ 0                  q*I_{phi(d)}   0 ]
       [ 0                  t_d^T          1 ]
   - LLL reduction. Find row with last coord = ±1; (s_d, e_d) = first two blocks.

2. CRT-combine over Q[x]:
   `s = CRT_list([s_d for d | n], [Phi_d for d | n])` in Q[x].
   Result has integer coefs in {-1, 0, 1}.

3. Lift s, e from Z to Rq for use as private key.
```

### 왜 격자가 풀리는가 (gap 계산)
For Phi_d with deg phi(d):
- Lattice dim = 2*phi(d) + 1
- det = q^{phi(d)}, vol_root = q^(phi(d)/(2*phi(d)+1)) ≈ q^{1/2}
- GH ≈ sqrt(dim/(2πe)) * vol_root
- Target ||s_d||, ||e_d|| typically ≤ 30 (sum of ternary, bounded by phi reduction)

For phi(d) = 96 (largest, d=n=420): dim 193, gap ≈ 9300/30 ≈ 300. Hermite needed `300^(1/193)` ≈ 1.030. **LLL는 1.022 → 충분히 작음**. LLL alone suffices.

### Sage code 핵심
```python
PR.<x> = PolynomialRing(ZZ)
PRq = PolynomialRing(GF(q), 'xq')
xq = PRq.gen()

a_poly_zz = sum(a_coefs[i] * x**i for i in range(n))
t_poly_zz = sum(t_coefs[i] * x**i for i in range(n))

recovered = {}
for d in divisors(n):
    phi_d = cyclotomic_polynomial(d)
    deg_phi = phi_d.degree()
    a_d_zz = a_poly_zz % phi_d
    t_d_zz = t_poly_zz % phi_d
    # ... lattice attack on dim 2*deg_phi + 1 ...

# CRT combine
PRQ = PolynomialRing(QQ, 'x')
s = CRT_list([PRQ(recovered[d][0]) for d in divisors(n)],
             [PRQ(cyclotomic_polynomial(d)) for d in divisors(n)])
```

### 성능
- n=420, q≈2^23, ternary: 모든 d | 420 (24개) 의 lattice 공격 + CRT = **~40초** (Sage docker)
- 가장 무거운 d=420 (deg phi=96, dim 193) 도 LLL alone

## 적용 범위
- Ring-LWE in `Z[x]/(x^n - 1)` for **composite n**
- Any `Z[x]/f(x)` where f = product of small-coef polynomials
- Variant: `x^n + x^{n/2} + 1` 같은 reducible polynomial 도 cyclotomic decomposition 가능
- 일반적으로 challenge가 "non-power-of-2 n" 또는 "cyclotomic factorization" 힌트 보이면 즉시 의심

## 출처
- HackTM CTF 2023: GLP420 — n=420, q=8383489, signature 위조
  - 작성자 (y011d4) writeup: cyclotomic factor + small lattice
- 관련 이론: Vulnerable Galois RLWE (eprint 2015/971), root-based PLWE attacks (arxiv 2410.01017) — distinguishing 위주이지만 small-coef 환경에서 key recovery로 직결

## 메모
- ψ_N projection 전략은 함정. 항상 cyclotomic factor (Phi_d) 으로 직접 분해. Q-CRT 가능 보장됨 (irreducible, coprime in Q[x]).
- Sage `CRT_list` 가 Z[x] 에서 실패하면 Q[x] 으로 변환. (정수 결과 보장)
- secret이 ternary 가 아닌 small Gaussian 이어도 동일 attack: lattice gap만 충분하면.
- f(x) 가 cyclotomic 아닌 경우 (e.g., x^n - x - 1): 일단 Z 위 인수분해 시도. 안 되면 F_q 위에서.
