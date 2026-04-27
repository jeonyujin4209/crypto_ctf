---
name: two-poly-shared-root-gcd-mod-n
description: 두 개의 (또는 그 이상) 다항식이 같은 비밀값 r을 root로 가지면, 격자(Coppersmith) 없이도 `gcd_modn(P1, P2)` 로 r 복구 가능. 단일 polynomial Coppersmith가 bound에 걸리는 케이스에 강력. 알 수 없는 모듈러스 n에서도 동작 — leading coeff non-invertible이면 부산물로 n 인수 발견.
type: attack
---

# Two-Polynomial Shared Root via GCD over Z/nZ

## 핵심 아이디어

비밀 정수 `r` (mod n) 에 대해 **두 개의 다항식**

```
P1(r) ≡ 0   (mod n)
P2(r) ≡ 0   (mod n)
```

이 동시에 성립하면, 두 다항식의 polynomial GCD를 `Zmod(n)` 위에서 계산:

```sage
P.<x> = PolynomialRing(Zmod(n))
def poly_gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
g = poly_gcd(P1, P2).monic()
# g가 degree 1 이면 g(x) = x - r  →  r 즉시 복구
```

대부분의 경우 `gcd`는 차수 1로 떨어지고 (P1, P2 가 r 외 공통 root를 가질 확률은 sweep). r은 `-g[0]` (monic 후).

## 언제 쓰나

- **비밀값 r 의 크기가 Coppersmith bound `n^(1/d)` 를 초과**해서 `small_roots` 가 안 잡힐 때
- **두 개 이상의 독립 관계식**이 r에 대해 mod n 으로 성립할 때
- 한 다항식이 e=3 짧은 지수의 Hastad 같은 단순 구조여도, 두 번째 관계식이 있으면 격자 시도 전에 GCD 먼저

전형 trigger:
- RSA에서 d, phi, p+q 같은 보조량 cube/square가 동시에 leak (예: HackTM 2023 d-phi-enc).
- Pollard p-1, p+1 변형: `g^(p-1)-1 ≡ 0 mod p` 같은 두 식.
- ECDSA / discrete-log 변형에서 두 signature/oracle equation 이 같은 nonce/key 공유.

## 예시: HackTM 2023 "d-phi-enc"

주어짐: e=3, n=pq, `enc_d = d^3 mod n`, `enc_phi = phi^3 mod n`, `enc_flag = m^3 mod n`.

핵심 식 유도:

```
ed = 1 mod phi    →   3d = 1 + k*phi   over Z,  k ∈ {1, 2}
27*enc_d ≡ (1 + k*phi)^3   (mod n)

Let u = n - phi = p+q-1.  Then 1 + k*phi ≡ 1 - k*u (mod n).
phi^3 = (n-u)^3 ≡ -u^3 (mod n).

→  P1(u) = (1 - k*u)^3 - 27*enc_d  ≡ 0 (mod n)
→  P2(u) = u^3 + enc_phi          ≡ 0 (mod n)
```

`u ~ 2*sqrt(n) ≈ n^{1/2}` → degree-2 또는 degree-3 단일 Coppersmith 모두 bound 초과로 실패.
하지만 `gcd(P1, P2) mod n` 은 즉시 `u + c0` 형태의 1차식. `u = -c0 mod n`.

`s = p+q = u+1` → `x^2 - sx + n = 0` 으로 p,q 분리 → 일반 RSA 복호.

## 주의사항

- **Leading coefficient 가 mod n 에서 non-invertible** 일 수 있음 (특히 P1 의 `-k^3` 같은 작은 상수가 우연히 n과 공약수). 그러면 polynomial division 단계에서 inverse 호출이 깨지는데, 그 자체가 `gcd(coef, n) = factor of n` 정보를 leak — 캐치해서 활용 가능.
- **두 다항식이 사실상 같은 정보** (P2가 P1의 배수) 면 GCD = P1 → 1차로 안 떨어짐. 파라미터/유도 점검.
- **둘 다 r을 root로 갖는다는 점**이 핵심. 한 쪽만 정확하면 무용. 유도 단계에서 mod n 등치 관계 모두 검증.
- k 같은 작은 unknown integer 가 있으면 가능한 값 다 brute (e.g., e=3 → k ∈ {1,2}; e=65537 면 k ∈ {1..e-1} 큰 범위라 다른 접근 필요).

## 구현 한 줄 패턴 (Sage)

```sage
P.<x> = PolynomialRing(Zmod(n))
P1 = ...   # vanishes at secret r mod n
P2 = ...   # also vanishes at r mod n
def G(a, b):
    while b: a, b = b, a % b
    return a
g = G(P1, P2).monic()
assert g.degree() == 1
r = ZZ(-g[0])  # done
```

## 출처

- HackTM CTF 2023 — d-phi-enc (y011d4 작): e=3 + enc_d + enc_phi → 두 다항식 GCD 한방.
- 일반론은 polynomial-time Coppersmith 대안 (2-equation low-density attack) 으로 well-known 이지만 CTF 풀이서 자주 잊혀짐.
