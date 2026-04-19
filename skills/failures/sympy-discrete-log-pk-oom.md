---
name: sympy-discrete-log-pk-oom
description: sympy.ntheory.discrete_log은 p^k 모듈러스에서 full group 전개로 OOM. p-adic lifting (Hensel)으로 환원
type: failure
---

# sympy discrete_log OOM on p^k

## 실패 패턴
`sympy.ntheory.residue_ntheory.discrete_log(n=p^k, a, b)`에서:
- 내부적으로 `totient(p^k) = p^(k-1)(p-1)` 차수의 full Pohlig-Hellman 시도
- p가 100-bit, k=2면 차수 ~200-bit → Pollard rho/BSGS 메모리 폭발 → **OOM 또는 수 시간 행**

## 해결책: p-adic Hensel Lifting

(Z/p^k)* 차수 = p^(k-1) * (p-1). 구조:
```
(Z/p^k)* ≅ Z/p^(k-1) (additive, principal units 1+pZ/p^k) × Z/(p-1) (Teichmüller, F_p*)
```

DLP를 두 파트로 분해:
1. **F_p* 부분**: `base^(p^(k-1))` 이 Teichmüller 성분만 남김 → 작은 DLP (p-1 차수)
2. **Principal unit 부분**: `x / Teichmüller(x)` 는 1 + p·something 꼴. Log는 선형 (Paillier처럼)

### 코드 스켈레톤 (k=2)
```python
# Given: a^x = b in (Z/p^2)*
# Step 1: k mod (p-1) via F_p DLP
a_mod_p = a % p
b_mod_p = b % p
x_mod_pm1 = discrete_log(p, b_mod_p, a_mod_p)  # 작은 차수 → OK

# Step 2: k mod p via Paillier-style log on principal units
# Define L(u) = (u-1)/p mod p for u = 1 mod p
a_teich = pow(a, p, p*p)  # Teichmüller lift
a_princ = (a * pow(a_teich, -1, p*p)) % (p*p)  # 1 + p·? part
b_teich = pow(b, p, p*p)
b_princ = (b * pow(b_teich, -1, p*p)) % (p*p)
L_a = ((a_princ - 1) // p) % p
L_b = ((b_princ - 1) // p) % p
x_mod_p = (L_b * pow(L_a, -1, p)) % p

# Step 3: CRT
x = crt([x_mod_pm1, x_mod_p], [p-1, p])
```

## 교훈
- `(Z/p^k)*` DLP는 **항상 분해** (Teichmüller × principal unit)
- sympy에 맡기지 말고 분해된 DLP 각각 해결
- Gaussian integer Z[i]/p^k도 같은 원리 (`attack/gaussian-int-padic-dlp`)

## 관련
- `attack/gaussian-int-padic-dlp` — Z[i]/p^2 에서 동일 패턴
- `attack/partial-pohlig-hellman-bounded-key` — k bound < order면 일부 factor만
- `tools/sage-dlp-fp-feasibility` — F_p* DLP는 Sage로 128-bit까지 OK
