---
name: crt-rsa-kp-kq-reduction-mod-e
description: CRT-RSA (k_p, k_q) 쌍 검색을 e^2 → e로 축소. p mod e만 iterate하면 k_p, k_q 둘 다 유일 결정 (p-1이 e의 역원 가져야 함)
type: attack
---

# CRT-RSA $(k_p, k_q)$ Reduction via `p mod e`

## 언제 쓰나

CRT-RSA 공격에서 미지수 $k_p, k_q \in [1, e-1]$ 쌍을 다 돌려야 하는 상황 ($(e-1)^2 \approx e^2$ 쌍). 보통 다음 식으로 연결됨:

$$
e \cdot d_p - 1 = k_p (p-1), \quad e \cdot d_q - 1 = k_q (q-1), \quad p q = n
$$

$e$가 중~대 크기면 ($e = 293$, $e^2 \approx 85000$) 외부 iteration이 무거움.

## 핵심 관찰

양변 mod $e$:

$$
e d_p - 1 \equiv -1 \pmod e \Rightarrow k_p (p-1) \equiv -1 \pmod e \Rightarrow \boxed{k_p \equiv -(p-1)^{-1} \pmod e}
$$

$k_p \in [1, e-1]$이므로 $p \bmod e$가 결정되면 $k_p$가 **unique**. 마찬가지로 $q \bmod e$에서 $k_q$.

그리고 $p q \equiv n \pmod e$이므로 $q \equiv n \cdot p^{-1} \pmod e$.

**결론**: $p \bmod e$ 하나만 iterate ($\in \{2, \ldots, e-1\}$) → $(k_p, k_q)$ 쌍 유일 결정. 후보 ~$e-2$개.

## 제외 조건

- $p \equiv 0 \pmod e$: $p$가 $e$의 배수인 경우 — $p$는 큰 prime이라 $e \nmid p$이므로 발생 안 함
- $p \equiv 1 \pmod e$: $(p-1)^{-1}$ 없음. challenge가 `(p-1) % e != 0` 강제하므로 서버 측에서 제외
- $q \equiv 0, 1 \pmod e$: 같은 이유로 skip

## 코드 패턴

```python
def candidate_pairs(n, e):
    pairs = set()
    for p_me in range(2, e):            # p mod e
        p_inv = pow(p_me, -1, e)
        q_me = (n * p_inv) % e
        if q_me == 0 or q_me == 1:
            continue
        kp = (-pow(p_me - 1, -1, e)) % e
        kq = (-pow(q_me - 1, -1, e)) % e
        pairs.add((kp, kq))
    return list(pairs)                  # 보통 e-2 ≈ 290개
```

$(p, q)$ symmetry → pairs set에 $(k_p, k_q)$와 $(k_q, k_p)$ 둘 다 들어갈 수 있음 (OK, 추가 iteration만).

## 효과

WACON 2022 RSA Permutation에서:
- 단순 $(k_p, k_q)$ 전체 검색: $292^2 = 85264$ pairs, backtrack total ~13분
- mod-$e$ 축소: 290 pairs, **2.3초** (~330× 빠름)

검색이 외부 loop인 상황에서 상수가 $e$-배 줄어드는 건 큼.

## 적용 가능 문제 유형

- Partial-$d_p$/partial-$d_q$ Coppersmith 공격 전 $(k_p, k_q)$ brute
- CRT-RSA faulty/leaked digit 공격 (이 skill이 쓰인 WACON RSA Permutation 같은)
- $d, d_p, d_q$ 정수 관계식 있는 어떤 CRT-RSA 공격이든 — 쓰일 수 있으면 항상 먼저 축소

## 주의

- $e$가 $p-1$, $q-1$과 coprime이라는 RSA 전제 조건 아래서만 유효
- $e$가 작을 때 ($e = 3, 17$) 어차피 $e^2$가 작아서 축소 의미 적음
- $e$가 합성수여도 OK. $p \bmod e$에서 $(p-1)^{-1}$ 계산 가능하면 됨 ($\gcd(p-1, e) = 1$ 필요)

## 출처

- WACON 2022: RSA Permutation (CryptoHack CTF Archive) — flag가 "Heninger_Shacham"이지만 HS 실제 파워는 **이 reduction과 합쳐졌을 때** 발휘됨
