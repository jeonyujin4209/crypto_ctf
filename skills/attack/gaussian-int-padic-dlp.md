---
name: gaussian-int-padic-dlp
description: Z[i]/(p^2)* DLP에서 norm map + Paillier-style log로 p-파트 O(1). k bits < order bits면 일부 prime만 CRT로 충분
type: skill
---

# Gaussian Integer DLP over Z[i]/(p^2)*

## 문제 구조
- `n = p^2`, p ≡ 3 mod 4 (또는 특정 mod 조건) 소수
- g의 order = p·q·r, 여기서 q=(p-1)/2 또는 (p-1)/6, r=(p+1)/12 또는 (p+1)/4 모두 소수
- 즉 `p-1 = 2q`, `p+1 = 12r` (case A) 또는 `p-1 = 6q`, `p+1 = 4r` (case B)
- **(p²-1) = 24·q·r** (두 case 모두). g = h^24 로 24-torsion 제거 → order p·q·r

## 핵심 통찰 1: Partial Pohlig-Hellman (크리티컬)

**private key k가 order보다 작으면 모든 prime factor를 풀 필요 없다.**

예: k는 256-bit urandom, order = pqr ≈ 2³⁸⁴ (p,q,r 각 ~128-bit).
- **p·q > 2²⁵⁴** 이므로 k mod (pq) 알면 최대 4개 candidate (k < 2²⁵⁶ ≈ 4·pq)
- r (p+1 쪽, 124-bit) 풀 필요 **없음**

**selection rule**: p, q, r 중 가장 **큰** prime 2개 선택 → CRT 모듈러스 최대화 → brute force 최소화

## 핵심 통찰 2: Norm Map + Paillier Log

Norm map `N(a+bi) = a² + b²`는 (Z[i]/p²)* → (Z/p²)* 준동형.

### k mod p (O(1))
```python
gp  = cpow(g, q*r, n)          # order p (in 1 + p·Z[i]/p²)
pubp = cpow(pub, q*r, n)
c1 = norm(gp)  % (p*p)         # c1 = 1 + p·a mod p²
c2 = norm(pubp) % (p*p)        # c2 = 1 + p·b mod p²
a = (c1 - 1) // p % p
b = (c2 - 1) // p % p
k_mod_p = b * pow(a, -1, p) % p
```
원리: (1+pa)^k = 1 + pak mod p² (이항정리 + p² = 0), Paillier 같은 구조.

### k mod q (F_p* DLP로 환원)
```python
gq  = cpow(g, p*r, n)          # order q
pubq = cpow(pub, p*r, n)
Ng  = norm(gq)  % p            # in F_p*, order q
Npub= norm(pubq) % p
# Sage: k_mod_q = discrete_log(GF(p)(Npub), GF(p)(Ng), ord=q)
```
q | (p-1)이므로 q-order 원소는 F_p^\*에 속함. **128-bit p + 127-bit prime subgroup = Sage 실측 49.6초** (PARI znlog는 index calculus, Pollard rho 아님). 자세한 타이밍은 `tools/sage-dlp-fp-feasibility` 참고.

### CRT + Brute Force
```python
# k ≡ k_mod_p (mod p), k ≡ k_mod_q (mod q)
x0 = crt([k_mod_p, k_mod_q], [p, q])
for i in range((2**256)//(p*q) + 2):
    cand = x0 + i*p*q
    if cand >= 2**256: break
    # try AES.new(cand.to_bytes(32,'big')).decrypt(ciphertext), check flag prefix
```

## 체크리스트
1. `k.bit_length() < order.bit_length()` 인가? → partial PH 적용
2. prime factor 중 **큰 것부터** 선택해서 CRT 모듈러스 > k size 만들기
3. p² 구조면 norm + Paillier log (component 추출 대신)
4. 128-bit F_p* DLP는 Sage `discrete_log(..., ord=q)` 그냥 돌리면 됨 (수 분~수십 분), 미리 포기 금지

## 관련 문제
- Unevaluated (TETCTF 2021) — 위 수식 그대로 적용, flag = `TetCTF{h0m0m0rph1sm_...}`
- Unimplemented (TETCTF 2021) — 같은 group 구조로 RSA-like decrypt, `f(p) = p³-p` 사용 (Lagrange)
