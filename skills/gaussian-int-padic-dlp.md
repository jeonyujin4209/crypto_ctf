---
name: gaussian-int-padic-dlp
description: Z[i]/(p^2)* DLP의 p-subgroup은 BSGS 불가(2^63). Hensel lifting으로 k_p = (h_p-1)/p * inv((g_p-1)/p) mod p 선형 해결
type: skill
---

# Gaussian Integer p-adic DLP (Z[i]/(p^2)*)

## 실패 원인
Unevaluated (TETCTF 2021): 군 차수 = p*q*r (p,q,r 모두 ~127-bit 소수).
Pohlig-Hellman + BSGS로 접근 → p-파트에서 sqrt(p) ≈ 2^63 스텝 → MemoryError.

**BSGS는 p가 60비트 이상이면 쓸 수 없다.**

## 핵심 원리: p-파트는 선형

Z[i]/(p^2)* 의 p-파트 = { x ∈ Z[i]/(p^2) : x ≡ 1 (mod p) }

이 부분군은 덧셈군 Z[i]/(p) ≅ GF(p^2) 와 동형:
```
φ: x ↦ (x - 1) / p  (mod p)
```
즉 `g_p = g^(order/p)` 가 `1 + p·a` 꼴이면:
```
g_p^k ≡ 1 + p·(k·a)  (mod p^2)
```

**DLP k mod p는 나눗셈 한 번:**
```python
def padic_dlp(g_p, h_p, p, n):
    """
    g_p, h_p: Complex elements of Z[i]/(n), both ≡ (1,0) mod p
    Finds k such that g_p^k = h_p, with 0 <= k < p
    """
    # Extract the first-order term: (x - 1) / p mod p
    def first_order(x):
        re = (x.re - 1) // p % p   # if re part: (re-1)/p
        im = x.im // p % p          # if im part: im/p
        return re, im

    g_re, g_im = first_order(g_p)
    h_re, h_im = first_order(h_p)

    # Solve k*g ≡ h (mod p) in Z[i]/(p) — try re or im component
    for g_val, h_val in [(g_re, h_re), (g_im, h_im)]:
        if g_val != 0:
            return h_val * pow(g_val, -1, p) % p
    raise ValueError("degenerate case")
```

## q, r 파트: GF(p^2) DLP으로 환원

차수 q = (p-1)/2 짜리 부분군은 Z[i]/(p^2) → Z[i]/(p) = GF(p^2) 로 환원 후 DLP.

p ≡ 3 mod 4 → Z[i]/(p) ≅ GF(p^2) 이고, GF(p^2)*의 차수 q 부분군 DLP는 Sage:
```python
F = GF(p^2, 'i', modulus=[1,0,1])
i = F.gen()
g_Fp2 = F(g_sub.re + g_sub.im * i)   # mod p
h_Fp2 = F(h_sub.re + h_sub.im * i)
k = discrete_log(h_Fp2, g_Fp2, ord=q)
```

q가 ~127비트이면 이것도 느릴 수 있음. q가 smooth하면 PH, 아니면 Pollard-rho (Sage 자동).

## 전체 흐름

```
order = p * q * r
g, pub, n = ...  # n = p^2

# 1. p-파트: Hensel lifting (O(1))
cofactor_p = q * r
g_p = cpow(g, cofactor_p, n)   # order = p
h_p = cpow(pub, cofactor_p, n)
k_p = padic_dlp(g_p, h_p, p, n)

# 2. q, r 파트: GF(p^2) DLP
cofactor_q = p * r
g_q = cpow(g, cofactor_q, n)   # mod p for Fp2 DLP
h_q = cpow(pub, cofactor_q, n)
k_q = dlp_in_Fp2(g_q, h_q, p, q)

# 3. CRT
k = crt([k_p, k_q, k_r], [p, q, r])
```

## 체크리스트
- `sqrt(prime_factor) > 2^30` 이면 BSGS 금지
- p^2 구조면 p-파트는 반드시 Hensel lifting 사용
- q, r이 (p-1)/2, (p+1)/12 꼴이면 GF(p^2)로 환원 가능

## 관련 문제
- Unevaluated (TETCTF 2021) — `order = p*q*r`, n = p^2, p ≡ 3 mod 4 ≡ 2 mod 3
