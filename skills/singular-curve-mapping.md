---
name: singular-curve-mapping
description: Singular EC (discriminant=0) → additive/multiplicative group 매핑으로 ECDLP trivially 해결
type: skill
---

# Singular Elliptic Curve → Multiplicative/Additive Group Mapping

## 유형
Elliptic Curve Discrete Log Problem (ECDLP) where the curve is **singular** (discriminant = 0)

## Trigger 패턴
다음 중 하나가 보이면 singular curve 의심:
- 곡선 파라미터 `(a, b)` 중 일부 또는 전부가 hidden, 점만 주어짐
- ECDLP인데 BSGS / Pollard rho 시도 전에 **discriminant 체크** 안 함
- "내가 만든 secret curve" / "custom parameters" 류 challenge 설명
- 곡선 식이 명시적으로 `y² = x³` (cusp) 또는 `y² = x³ + ax²` 같은 형태

**즉시 체크**: `Δ = -16(4a³ + 27b²)`. `Δ = 0`이면 singular → ECDLP 아니라 훨씬 쉬운 DLP.

## 왜 못 풀었나 (A)

### 시도 1: 표준 ECDLP 알고리즘
BSGS, Pollard rho, MOV, Smart's attack 모두 시도. 모두 fail 또는 시간 초과.
- BSGS: 너무 큼
- Pollard rho: O(√N) 너무 느림
- MOV: embedding degree 너무 큼
- Smart's: anomalous 아님

### 시도 2: 곡선 파라미터 복원만 하고 끝
`(a, b)`를 점들로부터 복원했지만, 그 다음에 어떻게 푸는지 모름. **곡선이 singular라는 걸 인지 못 함**.

### 핵심 깨달음
Singular curve의 non-singular 점들은 **`F_p*` (cusp는 `F_p+`) 와 isomorphic**. 즉 ECDLP가 multiplicative DLP (또는 additive trivial)로 환원됨.

## 어떻게 해결했나 (B)

### 1. 곡선 파라미터 복원 (필요시)
주어진 점 `G, Q`로부터 두 식:
```
y_G² ≡ x_G³ + a·x_G + b (mod p)
y_Q² ≡ x_Q³ + a·x_Q + b (mod p)
```
빼면 `(y_G² - y_Q²) ≡ (x_G³ - x_Q³) + a·(x_G - x_Q) (mod p)` → `a` 즉시 복원, `b`도.

### 2. Singular 종류 판별
`f(x) = x³ + ax + b`의 중근(double root) 위치 찾기:
- 중근 `α`: `f(α) = 0` and `f'(α) = 0` → `3α² + a = 0` → `α = -3b / (2a)` (또는 직접 풀이)
- `f(x) = (x - α)²·(x - β)`: **node** (β ≠ α) → multiplicative
- `f(x) = (x - α)³`: **cusp** (β = α) → additive

### 3a. Node case → `F_p*` mapping
Translation `x → x + α`로 중근을 원점으로 옮기면 `y² = x²(x + (β - α))`. 새 변수:
```
t = (β - α)
γ² = t  (즉 γ = sqrt(t) mod p, 존재해야 split node)
u = (y + γx) / (y - γx)
```
이러면 group law가 `F_p*`의 곱셈이 됨. ECDLP `Q = nG`가 `u_Q = u_G^n`이 되고, **`F_p*`에서의 DLP**.

`p - 1`이 smooth하면 Pohlig-Hellman로 즉시 풀림 (대부분의 challenge가 그러함).

### 3b. Cusp case → `F_p+` mapping (additive)
`y² = (x - α)³`. 변수:
```
u = (x - α) / y
```
이러면 `nG`의 `u`값이 `n · u_G (mod p)` (additive). DLP가 trivial:
```
n ≡ u_Q · u_G⁻¹ (mod p)
```

### 4. Pohlig-Hellman 마무리
node case에서 `n ≡ dlog(u_G, u_Q) mod (p-1)` → smooth factorization 활용.

```python
def singular_attack(p, G, Q):
    # 1. Recover (a, b) if hidden
    a, b = recover_curve(p, [G, Q])
    
    # 2. Check singular
    disc = (-16 * (4*a**3 + 27*b**2)) % p
    assert disc == 0, "not singular"
    
    # 3. Find double root
    alpha = (-3*b * pow(2*a, -1, p)) % p  # for y² = x³ + ax + b form
    # ... (translate, factor)
    
    # 4. Check node vs cusp
    f = lambda x: (x**3 + a*x + b) % p
    fprime = lambda x: (3*x**2 + a) % p
    if f(alpha) == 0 and fprime(alpha) == 0:
        # check if cusp (triple root)
        fpprime = (6*alpha) % p
        if fpprime == 0:
            # cusp
            uG = ((G[0] - alpha) * pow(G[1], -1, p)) % p
            uQ = ((Q[0] - alpha) * pow(Q[1], -1, p)) % p
            n = (uQ * pow(uG, -1, p)) % p
            return n
        else:
            # node — find γ, map to F_p*, dlog
            ...
```

## 적용 범위
- "Custom curve / hidden parameters" challenges
- 곡선 식 자체가 singular (discriminant 체크 빼먹기 쉬움)
- 의도적 backdoor 곡선
- **항상 ECDLP 풀기 전 discriminant 체크하는 습관**

## 핵심 교훈
ECDLP 만나면 다음 순서로 체크:
1. `Δ = 0`? → **singular curve attack** (이 skill)
2. `#E = p`? → Smart's attack (anomalous)
3. embedding degree 작음? → MOV / Frey-Rück
4. `#E` smooth? → Pohlig-Hellman
5. `n` (private key) 작음? → BSGS / Kangaroo
6. 위 다 아니면 → Pollard rho

**1번을 빼먹지 말 것.** 한 줄 체크로 challenge가 trivial 해질 수 있음.

## 출처
- CryptoHack: Elliptic Nodes (150pts, Elliptic Curves Parameter Choice)
  - hidden `(a, b)`, 두 점으로 복원 후 node singular 발견
  - `F_p*` mapping + Pohlig-Hellman으로 즉시 풀림
- Reference: Silverman, "The Arithmetic of Elliptic Curves", §III.2 (singular cubics)

## 메모
- Split node (γ ∈ F_p) vs non-split node (γ ∈ F_{p²}) 구분 필요. Non-split이면 `F_{p²}*`에서 dlog
- Char 2, 3 에서는 식이 다름 (Weierstrass 일반형 써야 함)
