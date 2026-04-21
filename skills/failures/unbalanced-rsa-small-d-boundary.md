---
name: unbalanced-rsa-small-d-boundary
description: Unbalanced RSA (p=N^β, β<0.5) with small d just above N^0.292: naive CF/BD 전부 실패. 큐빅 polynomial k(p-1)(N-p)+p≡0 mod e는 asymptotic 경계에 걸려 실제 challenge에서 작동하지 않음. 진짜 공격은 Maitra-Sarkar 또는 Herrmann-May sublattice 같은 고급 기법 필요.
type: failures
---

# Unbalanced RSA with Small d Just Above BD Bound: My Attempts Failed

## 문제 설정

- `N = p*q`, 1024-bit
- `p`는 256-bit (β_p = 0.25), `q`는 768-bit (β_q = 0.75) — 매우 unbalanced
- `d`는 300-bit, 조건 `d > N**0.292`만 통과. 표준 balanced Boneh-Durfee 경계(δ=0.292) 바로 위
- 예: "Unbalanced (ICC Athens)" — CryptoHack CTF Archive 2022

## 시도한 공격들 (모두 실패)

### 1. Wiener / Blömer-May / Nitaj CF variants

모든 CF 기반 공격이 실패:
- `e/N`, `e/(N - 2^{768})`, `e/(N - N^{0.75})`, `e/(N - N^β - N^{1-β} + 1)` 전부

**이유**: `|e/A - k/d|` 실측 ≈ 2^{-256} (s=p+q ≈ 2^{768} 때문), 필요 조건 `< 1/(2d²) = 2^{-601}`. 345 bit 부족.

Blömer-May 원 논문 바운드 `d < N^{3/4 - β/2}` (β=0.25면 N^0.625)가 있다고 주장하지만 이 바운드는 **실측 검증 실패**. CF가 이 경계에서 작동하려면 더 정확한 A 근사 필요한데 그런 방법이 없음.

### 2. Boneh-Durfee with unbalanced Y

BD polynomial `f(k, s) = 1 + k(N+1-s) mod e`, s = p+q ≈ 2^{768}.

Asymptotic 바운드 (basic): `X·Y² < e^{3/2}`. 우리: `2^{300+1536} = 2^{1836}` vs `e^{1.5} = 2^{1534}`. 302 bit 초과.
Herrmann-May sublattice: `X·Y² < e^{7/6} = 2^{1194}`. 642 bit 초과.
**Asymptotically infeasible.**

### 3. 큐빅 polynomial 접근 (가장 유망했지만 borderline)

`ed - 1 = k(p-1)(q-1)` + `q = N/p` 치환 → 양변 p 곱:
`p(ed - 1) = k(p-1)(N-p)`, mod e: `k(p-1)(N-p) + p ≡ 0 (mod e)`.

전개: `f(x, y) = -xy² + (N+1)xy - Nx + y ≡ 0 (mod e)`, x=k (~2^300), y=p (~2^256).

Newton polygon은 삼각형 `(0,1), (1,0), (1,2)`. Basic Jochemsz-May asymptotic 바운드 (polygon shifts, `c = min(i, j//2)`):
$$
\tfrac{2}{3} \log X + \log Y < \tfrac{4}{9} \log e
$$

이 바운드 계산 (β_p = 0.25, X_bits = 300, Y_bits = 256, e_bits = 1023):
- LHS = 200 + 256 = 456
- RHS = 454.67
- **실패 by 1.33 bit (asymptotically)**

전체 Coppersmith 바운드를 δ 관점에서:
$$
\delta < \tfrac{2}{3} - \tfrac{3\beta}{2}
$$
β = 0.25: δ < 0.292 — **balanced BD 바운드와 동일** (우연 아님, 같은 polynomial 구조).

### 4. Linear Diophantine lattice

`ed + k(s-1) ≡ 1 (mod N)` 선형화 후 lattice 구성. z = k·s 관계 encode 불가능하여 trivial solution `(0, 0, 1, 0)` 만 나옴.

### 5. Jochemsz-May defund-style 실측

작은 인스턴스 (margin 12.7 bit asymptotic)에서:
- m = 3~9 모두 HG threshold `e^m/sqrt(n)` 1-2 bit **초과**
- Gap이 m 증가해도 일정하게 유지 (slack term 때문)
- Root 추출 `I.variety()`가 trivial `(0, 0)` 만 반환

**LLL slack (2^{(n-1)/4} factor)이 asymptotic margin을 집어 삼킴**. BKZ(block=25)는 fplll `infinite loop in babai` 에러.

## 왜 실패했나

1. 큐빅 polynomial의 asymptotic 바운드가 challenge 파라미터에서 **정확히 경계 근처**. 여유 0.5~2 bit.
2. LLL 실측 slack 3+ bit이 이 여유를 초과함.
3. Maitra-Sarkar (2008) 같은 논문은 β=0.25면 δ < 0.315 가능하다고 주장하지만, 이는 내가 구현한 basic JM이 아닌 **더 강한 shift strategy** (Herrmann-May sublattice 확장) 필요. 구현 비용 큼.

## 올바른 공격은?

아마 다음 중 하나:
- **Maitra-Sarkar / Sarkar extended BD for unbalanced**: 큐빅 polynomial에 더 정교한 shift set 사용
- **Herrmann-May sublattice technique** 큐빅에 적용
- **Trivariate Coppersmith** with `yz = N` 제약 exact 처리
- 실제 솔버는 **flatter** 같은 특수 LLL 구현 또는 high block-size BKZ 사용할 수 있음

## 이 노트를 왜 저장

미래에 비슷한 "boundary δ, 불균형 β" 문제 보면:
- **CF variants 시도 금지** — 수학적으로 불가능 (확인됨)
- **Basic BD** 시도 금지 (asymptotically 불가)
- **큐빅 polynomial** + basic JM은 경계에서만 작동. 구체 파라미터로 asymptotic 먼저 검증하고, slack 고려한 safe margin (5+ bit) 있을 때만 시도
- 진지하게 풀려면 **Herrmann-May sublattice** 또는 **Maitra-Sarkar** 원 논문 구현 필요

## 참고: 올바른 margin 계산

큐빅 polynomial 공격이 가능한 조건:
$$
(2/3) \log X + \log Y + 5 \text{bit slack} < (4/9) \log e
$$

where slack ≈ log(lattice dim). For m=5, n=54, slack ~ 3-5 bit.

실용적 안전 마진: asymptotic 공식 LHS/RHS 차이가 **10+ bits** 여유 있어야.
