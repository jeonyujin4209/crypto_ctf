---
name: permuted-digits-hs-branch-prune
description: d_p, d_q가 hex digit permutation으로 주어지면 d = Σ σ[y_i]·B^i 선형 구조. CRT 항등식 mod B^(d+1) 증분 check로 σ backtrack
type: attack
---

# Permuted-Digit CRT-RSA: Heninger-Shacham-style Branch-and-Prune

## 문제 유형

CRT-RSA 비밀값 $d_p, d_q$의 **digit 표현**이 unknown permutation $\sigma \in S_B$ ($B = $ base, 흔히 16) 아래 주어짐:

- 서버가 준 $d_p'$: $d_p$의 각 hex digit $h_i$가 $\sigma(h_i)$로 바뀐 string
- $d_q'$도 같은 $\sigma$ (single permutation, 두 값 모두에 적용)
- $n = pq$ 공개, $e$ 공개
- 목표: $p, q$ 복구

WACON 2022 "RSA Permutation"이 prototype.

## 핵심 구조

### 1. $d_p, d_q$는 $\sigma$에 대해 **선형**

$d_p'[i] = y_i$ (위치 $i$ from LSB)라 하면 $d_p$의 해당 digit은 $\sigma(y_i)$. 따라서:

$$
d_p = \sum_i \sigma(y_i) \cdot B^i = \sum_{j=0}^{B-1} \sigma_j \cdot N_j^{(p)}
$$

where $N_j^{(p)} = \sum_{i: y_i = j} B^i$. $B=16$ unknown $\sigma_0, \ldots, \sigma_{15} \in \{0, \ldots, 15\}$ (permutation, 모두 distinct).

### 2. CRT-RSA 항등식 (check equation)

$e d_p - 1 = k_p (p-1)$, $e d_q - 1 = k_q (q-1)$, $pq = n$. 곱하면:

$$
(e d_p + k_p - 1)(e d_q + k_q - 1) = k_p k_q n
$$

정수 등식. $d_p$는 $\sigma$에 선형이므로 이건 $\sigma$에 대해 **quadratic over integers**. 

### 3. Mod $B^{d+1}$ 증분 체크

LSB부터 $d$번째 hex 처리하면 $d_p \bmod B^{d+1}$ 결정됨 (처음 $d+1$ positions의 $\sigma$ 값만 필요).

Depth $d$에서:
$$
(e \cdot \text{dp\_mod} + k_p - 1)(e \cdot \text{dq\_mod} + k_q - 1) \equiv k_p k_q n \pmod{B^{d+1}}
$$

실패하면 branch prune. 성공률 ~$1/B$.

## 알고리즘

```
1. (k_p, k_q) 후보 결정 — e.g. crt-rsa-kp-kq-reduction-mod-e로 ~e개
2. 각 pair에 대해:
   σ = {} (partial map from y to σ(y))
   rec(depth=0, dp_mod=0, dq_mod=0):
     if σ fully assigned:  verify 정수 factorization, return
     y1, y2 = y_p[depth], y_q[depth]
     for each consistent assignment of σ[y1], σ[y2]:   # 새로운 y만 branching
         new_dp = dp_mod + σ[y1] * B^depth
         new_dq = dq_mod + σ[y2] * B^depth
         if (e*new_dp+kp-1)(e*new_dq+kq-1) ≡ kp*kq*n  (mod B^(depth+1)):
             rec(depth+1, new_dp, new_dq)
```

Branching 지점: $y_1 = y_{p,d}$가 아직 σ에 없는 경우만 새 값 시도 (나머지 $B - |\sigma|$개 선택). 이미 할당된 $y$면 single check.

## 왜 빠른가

- 각 depth마다 $1/B$ 확률로 check 통과 → 잘못된 σ path는 몇 depth 안에 prune
- 전체 $B!$ permutation 탐색 ($16! \approx 2 \times 10^{13}$) 대신 tree depth ~20 ($B$ 값 모두 처음 나타날 때까지), 각 depth 평균 branching factor $< 2$
- $(k_p, k_q)$ 축소 skill과 결합: WACON "RSA Permutation" 2.3초 해결 (일반 brute는 14분)

## 일반화

- **$B \ne 16$**: 십진수 digit permutation (소문제 만들기 가능), base-32/64도 가능. Mod $B^{d+1}$ check 그대로
- **Partial permutation** (일부 digit만 shuffle): branching 지점만 바뀜
- **Digits with bias** (e.g. digit 0이 특수): 조건만 추가
- **Single value permuted** ($d_q$만 leak): $d_q$ linear 하나 + factorization 체크. 더 쉬움

## 구현 주의

- **LSB부터 처리**. MSB부터 하면 modular check가 full $d_p$를 요구해서 증분 안 됨
- $d_p$ 홀수 조건 (LSB hex digit 홀수): 단독으론 weak이지만 depth 0 branching을 절반으로 줄이는 초기 제약으로 유용
- σ fully assigned 되는 depth 조기 감지 → verify_full로 빠져나와서 남은 depths 생략
- Python bigint 곱셈이 depth 따라 커지지만 보통 depth 30 이내에 σ 결정되므로 mod 크기는 $\le B^{30}$로 제한

## Heninger-Shacham과의 관계

HS 원본: random bit leak 상황에서 CRT-RSA 전체 키 ($p, q, d, d_p, d_q$) 복구. Bit level branch-and-prune.

이 skill: bits 대신 **digit permutation** (구조화된 leak)로 환원. 같은 아이디어 — 모듈로 증분 check, branching-candidate, 실패 path 조기 prune.

Flag ("shuffle_all_the_hexes_but_still_Heninger_Shacham")가 직접 지칭.

## 출처

- CryptoHack CTF Archive 2022 WACON: RSA Permutation — 2048-bit RSA, $e=293$, 전체 hex digit permutation
- Heninger-Shacham (2009) "Reconstructing RSA Private Keys from Random Key Bits" — 원리
