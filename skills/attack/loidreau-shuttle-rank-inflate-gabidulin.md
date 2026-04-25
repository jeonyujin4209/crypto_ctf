---
name: loidreau-shuttle-rank-inflate-gabidulin
description: Loidreau-style PKE (G' = S · G · P⁻¹ with P entries in λ-dim F_q-subspace V) → 우측 P-곱으로 distortion 제거 → error rank가 t·λ로 팽창해도 ≤ ⌊(N-K)/2⌋면 표준 Gabidulin Gao decoder로 복호
type: skill
---

# Loidreau-style Rank-Metric PKE: Right-multiply by P, Decode Inflated Error

## 유형
Loidreau PKE (rank-metric McEliece의 λ-subspace variant). 공개키:
```
G_pub = S · G_Gab · P⁻¹    (k × n over F_{q^m})
```
- `G_Gab[j,i] = g_i^(q^j)`  : Moore matrix (Gabidulin generator), `g_i` linearly independent over F_q
- `S` : k×k invertible, scrambler
- `P` : n×n invertible **with entries in λ-dim F_q-subspace V ⊂ F_{q^m}** (the trapdoor)
- ciphertext: `c = m · G_pub + e`, where `e` has F_q-rank ≤ t

원본 Loidreau (2017) ePrint 2017/421. λ=2 for security; CTF 변형은 종종 λ=3 또는 P, V 노출.

## Trigger 패턴
- Moore-matrix 형태 generator (`g_i^(q^j)`) 또는 명시적 Gabidulin code
- 우측에 `P⁻¹` (또는 `Q`) 곱해진 generator, P 엔트리가 작은 F_q-subspace에 갇혀 있음
- error의 F_q-rank가 명시되어 있거나 sparse rank로 생성됨
- `t · λ ≤ ⌊(n - k)/2⌋` 만족 ← decoder capacity 내에 있음
- **CTF context**: 챌린지가 `g_i, S, P, V` 일부 또는 전부 노출 (정상 Loidreau는 P를 비밀로 둠 — 노출되면 즉시 무너짐)

## 핵심 아이디어

### Right-multiply trick
```
c = m · S · G_Gab · P⁻¹ + e
c · P = (m · S) · G_Gab + (e · P)
```
이제 좌변이 표준 Gabidulin code (gen = G_Gab) 의 **codeword + error** 형태.

### Error rank inflation (필수 계산)
- `e` ∈ F_{q^m}^n with F_q-rank ≤ t  → 모든 컴포넌트가 t-dim subspace U = span_{F_q}(u_1..u_t)
- `P` 엔트리 ∈ V (λ-dim subspace = span_{F_q}(v_1..v_λ))
- `(e · P)_j = Σ_i e_i · P[i,j]` ∈ span_{F_q}({u_a · v_b : 1≤a≤t, 1≤b≤λ})

따라서 **rank(e · P) ≤ t · λ** (in F_{q^m} as an F_q-vector space).

Gao decoder (또는 BMA) 가 `⌊(n - k)/2⌋` 까지 보정 → `t · λ ≤ ⌊(n - k)/2⌋` 이면 복호 성공.

### Recovery
1. `c' = c · P` (= `m_S · G_Gab + e'` with rank(e') ≤ tλ)
2. Sage Gabidulin decoder로 `c'` → codeword
3. `loom.solve_left(codeword)` → `m_S = m · S`
4. `m = m_S · S⁻¹`

## 구현 (Sage)

```python
from sage.all import *

# 환경: Fqm = GF(q^m, modulus=...), pegs (= g_i, n개), S (k×k), P (n×n)
# G_pub (k×n), c (length-n) 모두 주어짐 가정

R = PolynomialRing(GF(q), 'x')
Fqm = GF(q**m, 'a', modulus=R(modulus_coeffs))

loom = Matrix(Fqm, k, n, lambda j, i: pegs[i] ** (q**j))
assert S * loom * P.inverse() == G_pub  # sanity

y = c * P  # rank-inflated codeword

C = codes.GabidulinCode(Fqm, n, k, sub_field=GF(q), evaluation_points=pegs)
D = C.decoder()  # Gao decoder by default
codeword = D.decode_to_code(y)

m_S = loom.solve_left(vector(Fqm, codeword))
m   = m_S * S.inverse()
```

### Sage API 메모
- `codes.GabidulinCode(F, n, k, sub_field=Fq, evaluation_points=pegs)` — `sub_field=Fq` 명시 필수 (default base field 추론 잘못함)
- `evaluation_points=pegs` 안 주면 기본 basis 사용 → 챌린지의 pegs와 다른 코드 만들어짐
- `D.decode_to_code(y)` : 보정된 codeword 반환. `decode_to_message(y)` 도 있지만 메시지 변환 컨벤션이 달라서 `loom.solve_left` 직접 푸는 게 안전

## 왜 못 풀던 패턴

### 삽질 후보 1: 좌측 S만 보고 BMA 직접
"loom 알고 S 알면 BMA로 풀자" — S를 좌측에서 곱한 뒤에도 P⁻¹가 우측에 살아있어서 standard Gabidulin이 아님. P 곱하기 전엔 의미 없음.

### 삽질 후보 2: error rank 계산 누락
`t · λ` 인플레이션을 계산 안 하면 "rank-5 error를 5로 처리"라고 착각, decoder가 망함.
**필수**: `t · λ vs ⌊(n-k)/2⌋` 부등식을 먼저 체크.

### 삽질 후보 3: `decode_to_message` 직접
Sage의 GabidulinCode message space는 skew polynomial coefficient. `m_S = decoded_message`가 아닐 수 있음. **codeword 받아서 generator로 solve_left 하는 게 직관적이고 안전**.

## Trigger 요약 (skill 사용 체크리스트)
1. ✅ Generator가 `S · M · P⁻¹` 형태, M이 Moore matrix
2. ✅ P 엔트리가 λ-dim F_q-subspace V에 갇힘 (or P, V 노출)
3. ✅ error의 F_q-rank ≤ t 가 명시
4. ✅ `t · λ ≤ ⌊(n - k)/2⌋` 확인
5. ✅ `c · P` 계산 → Gabidulin Gao decoder → `solve_left` for `m · S` → `m`

## 일반화
- **λ=1** (`P` ∈ GL_n(F_q)): trivial — P가 이미 F_q-matrix면 error rank 그대로, standard Gabidulin
- **P 비공개**: 정상 Loidreau. `t · λ < ⌊(n-k)/2⌋` 일 때 indistinguishability 깨지는 distinguisher 공격 (Coggia-Couvreur 2020 등) 필요
- **다른 rank-metric 코드**: LRPC / RQC / ROLLO 같은 변형도 *generator transform* 구조 비슷. P 곱하기 전 후 rank 계산 동일 원리

## 출처
- UMDCTF 2026 *weave*: λ=3, t=5, n=40, k=8, q=2, m=43. P, V 모두 노출 (read-me: "every piece of the cipher lies open on the table"). `5 · 3 = 15 ≤ ⌊(40-8)/2⌋ = 16` 으로 정확히 한 칸 여유 → Gao decoder 일발.
- 원전: Loidreau, *A New Rank Metric Codes Based Encryption Scheme*, PQCrypto 2017.
- Sage `codes.GabidulinCode` (sage.coding.gabidulin_code).

## 메모
- 챌린지 명 "weave/warp/shuttle/loom" = 베틀 용어. shuttle(북) 이 P, fibers 가 V basis, loom 이 Gabidulin generator. Loidreau cryptosystem의 시각적 mnemonic.
- `t·λ` 가 capacity 정확히 boundary 근처면 generic 가정 깨질 수 있음 (random에서 rank가 t·λ보다 작게 나올 수 있고, 같게 나올 수도 있음). 일발 안 되면 우선 더 작은 디코딩 반경(`tau`)으로 시도해 볼 가치 있음 — 다만 Gao는 unique decoding이라 t·λ ≤ floor((n-k)/2) 만 만족하면 항상 성공.
