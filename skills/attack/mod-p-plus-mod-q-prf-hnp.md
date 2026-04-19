---
name: mod-p-plus-mod-q-prf-hnp
description: Weak PRF f(x) = (prod mod p + prod mod q) mod p with p >> q 구조. prod = <k, h>, output ≈ r_p + r_q (wrap 확률 q/p ≈ 0). <k,h> ≡ out - r_q (mod p)로 변형 → r_q 짧은 slack HNP 격자 16+N+1 dim BKZ
type: attack
---

# HNP on "mod p + mod q" Weak PRFs

## 유형
공식: `f(x) = (prod % p + prod % q) % p`  where `prod = <k, h(x)>`
- `k` 비밀 키 (단일 or 다차원 256-bit 등)
- `h(x)` 알려진 hash-derived 벡터
- `p` 큰 소수 (≈ 2^257), `q` 작은 소수 (≈ 2^128)
- **p >> q** 가 핵심

`chal.py`의 `Generator4` 스타일: key가 16개의 256-bit 값, h는 iterated sha256, p/q random.

## 왜 공격 가능한가
`r_p + r_q` 계산에서 `r_p < p`, `r_q < q << p`이면 대부분 `r_p + r_q < p`, 즉 **wrap-around 없음** (wrap 확률 ≈ q/p → 무시).

Wrap 없다고 가정하면:
```
output = r_p + r_q  (정수 합, reduction 없음)
→  r_p = output - r_q
→  <k, h> ≡ output - r_q  (mod p)
```
여기서 `r_q = <k, h> mod q` 이고 `r_q ∈ [0, q)`가 **짧다**.

이건 고전적 **Hidden Number Problem** 변형:
- 주 미지수: k (16 × 256-bit = 4096 bits)
- slack: r_q_j (N × 128 bits)
- 각 쿼리: 1개의 mod-p 선형 방정식 (256-bit 정보)

## 격자 구축 (N 쿼리 기준)

차원: `16 + N + 1`

```
Row i (i=0..15)   : [ e_i (16) | W_r * H[i][0..N-1] (N) | 0 ]
Row j (j=0..N-1)  : [ 0 (16)   | W_r * p * e_j (N)       | 0 ]
Last row (target) : [ 0 (16)   | -W_r * outs[0..N-1] (N) | W_K ]
```

**Weights**:
- `W_r = q` (or 2^q_bits): r_q slack을 k와 같은 스케일로 올림 (`W_r * r_q ≈ W_r * q ≈ q² ≈ 2^256`)
- `W_K = 2^256`: 마지막 embedding 좌표도 k 크기로

Target short vector:
```
(k_1, ..., k_16, -W_r * r_q_1, ..., -W_r * r_q_N, W_K)
```
Norm ≈ `√(17+N) * 2^256`.

## N 선택 (Gauss heuristic)

Lattice vol = `1^16 * (W_r * p)^N * W_K = p^N * q^N * 2^256 = 2^{385*N + 256}`.

Gauss heuristic ≈ `√(dim/(2πe)) * vol^(1/dim)`:
| N  | dim | Gauss bits | Target bits | Ratio | OK? |
|----|-----|------------|-------------|-------|------|
| 30 | 47  | 252        | 259         | +7    | ✗ (target longer) |
| 35 | 52  | 265        | 259         | -6    | 경계 |
| 40 | 57  | 276        | 259         | -17   | ✓ |
| 50 | 67  | 294        | 259         | -35   | ✓ |

**N=40이 안전한 최소**. 더 많으면 BKZ 더 빨리 수렴.

## BKZ 및 복구

```python
# Sage
L = M.BKZ(block_size=20)
# 각 행에 대해 last coord = ±W_K 찾기
for r in range(dim):
    row = L.row(r)
    last = int(row[16+N])
    if last % W_K != 0: continue
    c = last // W_K
    if abs(c) != 1: continue
    # 후보 k 추출
    k = [c * int(row[i]) for i in range(16)]
    ...
```

### k_i 부호 처리 — **Critical gotcha**
LLL/BKZ는 `||k||` 최소화를 선호: 각 `k_i ∈ [-p/2, p/2]`로 정규화.
- 참 `k_i < p/2`: LLL이 그대로 반환 → OK
- 참 `k_i > p/2`: LLL이 `k_i - p < 0` 반환 → **검증 실패 (mod q 때문)**

해결: 각 `k_i`를 `k_i mod p`로 정규화 후 `[0, 2^256)` 범위로 조정:
```python
k_mod = [ki % p for ki in k_raw]
k_canon = [ki if ki < 2**256 else ki - p for ki in k_mod]
# 검증
assert all((sum(k_canon[i] * H[i][j] for i in range(16)) % p + sum(...) % q) % p == outs[j] for j in range(N))
```

**왜 그냥 k % p 를 쓰지 못하나?**: `k_i - p`로 shift하면 `prod`도 `prod - p*H_i` 변함 → `prod mod q`도 `(p mod q) * H_i`만큼 변함. p % q ≠ 0이라 결과가 틀림. **반드시 k_i를 [0, 2^256)**로 맞춰야 실제 키.

## 구현 체크리스트
- [ ] **H matrix shape**: 16 rows × N cols (= H[i][j] where i = key index, j = query index). Transpose 확인
- [ ] p, q가 실제 256-bit / 128-bit 경계인지 체크 (`p.bit_length()`)
- [ ] BKZ block_size 20이면 dim 50~70 OK. 더 크면 30 권장
- [ ] Weights: `W_r = q`로 충분 (scaling만 맞추면 됨)
- [ ] Sign handling: `c_target = last // W_K`가 ±1인지, 그리고 k_i에 대해 mod p → [0, 2^256) canonical 변환
- [ ] `json.dumps`에 sage Integer 섞이면 터짐 → `int(ki)` 명시 변환

## Wrap 확률 제어
wrap이 일어나면 그 쿼리에서 r_p + r_q ≥ p → `output = r_p + r_q - p`, 가정 위반.
- 확률: `q/p ≈ 2^{-(p_bits - q_bits)} = 2^{-129}` for Gen4
- 실전: 거의 절대 안 일어남. 40 queries에서 wrap 0개 (시뮬레이션 확인)
- 혹시 wrap 있으면 해당 쿼리 제외하고 재시도 (안전장치)

## 적용 범위
- 모든 `f = (<k, h> mod p + <k, h> mod q) mod p` 형태
- q << p면 HNP 잘 됨. q ≈ p면 노이즈 너무 큼 → 불가
- key 차원 ≤ ~30까지는 BKZ로 가능. 더 크면 격자 dim 증가로 어려움

## 출처
- CryptoHack CTF Archive 2022: Dark Arts (CODEGATE 2022)
  - Generator4: p ≈ 2^257, q ≈ 2^128, key 16×256-bit, h iterated sha256
  - N=40 dim 57, BKZ-20 in 7s on sage docker
  - Canonical k 처리로 verify 성공
- 이론 배경: Boneh-Ishai-Passelègue-Sahai-Wu "Darkmatter" PRF 계열
