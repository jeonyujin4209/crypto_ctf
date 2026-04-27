---
name: extension-field-pollard-pk-minus-1
description: n = p*q*r 같이 hidden factor 가 q = (p^k - 1)/(p - 1) = 1 + p + ... + p^(k-1) 형태로 묶여 있으면, F_{p^k}* 의 order 가 (p-1)*q 라 q | n 이 자동 성립. (Z/nZ)[x]/(random monic deg-k) 에서 random^n 을 계산하면 mod p 결과가 F_p 부분(상수항)에만 살아남음 → x, x^2, ... x^(k-1) 계수가 ≡ 0 mod p → gcd(coef, n) = p. Pollard p-1 의 extension-field 일반화.
type: attack
---

# Extension-Field Pollard `p^k - 1` Factorization

## 적용 트리거

`n = p * q * r * ...` 인데 hidden factor 중 하나가 다음 형태:

```
q = 1 + p + p^2 + ... + p^(k-1) = (p^k - 1) / (p - 1)
```

전형적으로 `k = 2, 3` (k=2 면 q = 1+p, k=3 면 q = 1+p+p^2 — "Sus" ImaginaryCTF 2023).
또는 `n = p*q` 단독에서 q 가 위 형태인 경우도 동일.

## 왜 통하나

`F_{p^k}*` 의 order = `p^k - 1 = (p - 1) * q` (위 정의에 의해). 따라서:

- `q | |F_{p^k}*|`
- `n = p*q*r*...` 가 `q` 를 인수로 가짐
- `n` 자체가 `(p-1)` 와는 일반적으로 서로소 (운 좋게 일부 인수 공유 가능)

이제 `(Z/nZ)[x] / f(x)` 를 잡되 `f` 가 mod p 에서 **irreducible** 인 monic 차수 k 다항식이면, mod p 로 보면 이 ring 은 `F_{p^k}` 와 동형. random `g ∈ R` 을 뽑아 `g^n` 을 계산하면:

- `g^n mod p` 는 `F_{p^k}*` 안에서 `g^n`. n 이 q 의 배수이므로 `g^n` 의 order 는 `(p-1)` 의 약수.
- `(p-1)` 의 모든 원소는 `F_p ⊂ F_{p^k}` 안에 있음 (subfield). 즉 **constant term 만 nonzero**, x, x^2, ..., x^(k-1) 계수는 0 mod p.

그러므로 `g^n ∈ R` 의 lift 의 x^i (i = 1..k-1) 계수는 `≡ 0 (mod p)` → `gcd(coef_i, n) = p` (또는 p 의 배수, but p 가 가장 작은 인수면 정확히 p).

mod q, mod r 부분에선 `g^n` 이 generic 값이라 nonzero — 그래서 gcd 가 trivial 로 떨어지지 않음.

## Sage 한 줄 (k=3 예시)

```sage
R = Zmod(n)["x"]
x = R.gen()
for _ in range(50):
    a, b, c = [ZZ.random_element(0, n) for _ in range(3)]
    f = x^3 + a*x^2 + b*x + c
    Q = R.quotient(f)
    g = Q.random_element()
    h = (g^n).lift()
    coefs = list(h)
    for i in range(1, 3):
        if i < len(coefs):
            d = gcd(ZZ(coefs[i]), n)
            if 1 < d < n:
                p = d  # likely the small prime factor
                break
```

## 일반 k

같은 패턴으로:
- k=2: `q = 1 + p`. ring 을 `(Z/nZ)[x]/(x^2+ax+b)` 로 구성, `g^n` 의 x 계수 → gcd. 이건 단순 Williams p+1.
- k=3: 위. ImaginaryCTF Sus.
- k≥4: `q = 1 + p + ... + p^(k-1)`. 동일 절차, deg-k 다항식, x..x^(k-1) 계수 중 nonzero 인 것 골라 gcd.

## 주의사항

- **f 가 mod p 에서 irreducible 일 확률** ≈ `1/k` (Mobius 공식). 50번 시도면 거의 항상 한 번은 잡힘.
  - `f` 가 reducible 이면 `R mod p` 가 `F_p^k` 안 됨 (직합 형태). 그래도 random `g^n` 의 일부 계수가 mod p 0 되는 경우 있어 종종 통함.
- **`g` 가 `F_{p^k}*` 의 entire group 에 균등 분포**해야 함. `g` 의 order 가 우연히 (p-1) 의 약수면 trivial gcd 만 나옴 — 다음 시도로 넘어감.
- gcd 결과가 `p` 가 아니라 `p*q` 나 다른 합성수일 수 있음. 길이/소수 검사 후 사용. 보통은 p 가 가장 작아서 깔끔히 떨어짐.
- p 복구 후 `q = sum(p^i for i in range(k))`, `r = n // (p*q)` 로 분해.

## 비교: Coppersmith 가 안 되는 이유

`f(x) = 1 + x + ... + x^(k-1)` 또는 `x*(...)` mod `p*q` 의 small root 는 Howgrave-Graham bound `n^(β^2/d)` 에 걸림.
n = pqr (3070 bit), β = log(pq)/log(n) ≈ 1/2, d = k=3 → bound `n^(1/12) ≈ 256 bit` 인데 p 는 512 bit. 정확히 2배 부족하고 lattice 로는 못 메움.
**대안 = 이 extension-field Pollard.**

## 출처

- ImaginaryCTF 2023 "Sus" (maple3142). 단독 트릭으로 30초 내 해결.
- 일반론은 Bach, Lenstra & Pomerance 의 cyclotomic factoring 분석 (Phi_k(p) factor 활용).
