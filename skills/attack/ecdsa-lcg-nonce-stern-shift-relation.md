---
name: ecdsa-lcg-nonce-stern-shift-relation
description: ECDSA nonce가 unknown LCG (a,b,p)에서 나오면 ECDSA 차분 kk_i = u_i*d + v_i mod q에 Stern shift trick 적용. 인접 두 shift를 augment해 a 소거 후 LLL로 short integer relation 추출 → kernel로 kk_i 복구 (up to scalar) → d 복구
type: skill
---

# ECDSA + LCG Nonce: Stern-Shift Integer Relation Lattice

## 유형
ECDSA (or DSA/Schnorr) signatures where nonces come from an LCG with **unknown** modulus p, multiplier a, increment b. Even when p > q (so nonces are not simply "small"), the linear LCG structure gives enough algebraic constraints.

## Trigger 패턴
- `k_{i+1} = a*k_i + b (mod p)` and a, b, p, x_0 all secret
- N (≥ 16) ECDSA signatures share the same private key d
- `p` larger than curve order `q` (so the usual "biased nonce" HNP doesn't directly apply)
- Challenge name contains "LCG", "linear congruential", or generator output is repeatedly fed back

## 핵심 아이디어

### Step 1 — ECDSA difference is linear in d
From `s_i ≡ k_i^{-1}(z_i + r_i d) (mod q)`:
```
k_i ≡ s_i^{-1} z_i + s_i^{-1} r_i · d   (mod q)
```
Take consecutive differences `kk_i := k_{i+1} - k_i`:
```
kk_i ≡ u_i·d + v_i  (mod q)
where  u_i = r_{i+1}/s_{i+1} - r_i/s_i,  v_i = z_{i+1}/s_{i+1} - z_i/s_i  (mod q)
```
Each `kk_i` is bounded in absolute value by p (LCG difference).

### Step 2 — Stern lattice with two shifts (cancel a)
LCG ⇒ `k_{i+1} - k_i ≡ a (k_i - k_{i-1}) (mod p)`, so `kk_{i+1}/kk_i ≡ a (mod p)`. Hence any integer linear combination `Σ c_j · kk_{i+j}` that holds for one starting index `i` also holds for the next index `i+1` (with the same c). We don't need to recover `a`; we just need integer relations among the `kk` values.

Build the lattice over (u_i, v_i, u_{i+1}, v_{i+1}) with the standard Stern HNP embedding:

```
M = [ U₀ | V₀ | U₁ | V₁ |  I_{n-2} ]    ← n-2 rows of "real signatures"
    [ q  | 0  | 0  | 0  |   0      ]
    [ 0  | q  | 0  | 0  |   0      ]
    [ 0  | 0  | q  | 0  |   0      ]
    [ 0  | 0  | 0  | q  |   0      ]
```
where U₀ = (u_0..u_{n-3})ᵀ, V₀ = (v_0..v_{n-3})ᵀ, U₁ = (u_1..u_{n-2})ᵀ, V₁ = (v_1..v_{n-2})ᵀ.

Scale the first 4 columns by a huge weight (e.g. `2**1000`) so LLL is forced to zero them out. The remaining (n-2)-component rows are integer combinations `c` such that `Σ c_j · kk_j ≡ 0 (mod q)` AND `Σ c_j · kk_{j+1} ≡ 0 (mod q)`. Since LLL outputs short c's and `|kk_j| < p ≪ q · (lattice scale)`, the relations actually hold over **Z**, not just mod q.

### Step 3 — Recover kk via kernel
Treat `kk_0..kk_{n-1}` as unknowns. Each relation `c` (applied at shifts 0 and 1) gives 2 linear equations:
```
Σ c_j · kk_{j+0} = 0      Σ c_j · kk_{j+1} = 0
```
Stack many such equations (use first ~k LLL rows). Form the coefficient matrix A (rows = equations, cols = symbolic kk_0..kk_{n-1}). The right kernel of A over Z is **1-dimensional**: a basis vector gives the true `kk` sequence up to sign / scalar.

In Sage:
```python
PR = PolynomialRing(ZZ, [f"kk_{i}" for i in range(n_kk)])
sym = PR.gens()
eqs = []
for row in M[:11]:
    comb = [int(x) for x in row[4:]]
    for shift in range(2):
        eqs.append(sum(a*b for a,b in zip(comb, sym[shift:shift+(n_kk-1)])))
A, _ = Sequence(eqs).coefficients_monomials()
ker = A.right_kernel().basis_matrix()   # 1 x n_kk
```

### Step 4 — Recover d
Once you have `kk_0`, use:
```
d = (kk_0 - v_0) / u_0  mod q
```
Try both signs `±ker[0]`.

## 주의 / 디버깅
- **Lattice 차원**: 17 signatures → 16 differences → 14 (start, +1 shift) rows → matrix 18x18. `M[:, :4] *= 2**1000`.
- **확인**: kernel dimension must be 1. If 0 or >1, get more relations (raise `M[:11]` slice) or shift more.
- **Two-sign ambiguity**: kernel is up to ±1 scalar. Try both, decrypt, eyeball flag.
- 수식이 `kk_i ≡ a · kk_{i-1} (mod p)`이지 mod q 아님. 우리가 LLL로 활용하는 건 어디까지나 `kk_i ≡ u_i d + v_i (mod q)`이고, integer relation은 **size argument** (kk < p < q·W)로 통합.
- Why two shifts? With one shift only, kernel is huge (we'd just be solving `Σ c_j kk_j = 0` which has many solutions). Two shifts pins down the sequence's LCG structure.

## 적용 범위
- HITCON CTF 2024 — ECLCG (이 skill의 출처). p ≈ 311-bit, q ≈ 256-bit, 17 sigs
- "Easy DSA: LCG" — 같은 골격 (pruned)
- 더 일반: ECDSA/DSA nonce가 임의의 unknown LCG, p가 q보다 크든 작든 무관 (size 비교만 lattice scale 결정)

## 외부 출처
- Connor McCartney writeup: https://connor-mccartney.github.io/cryptography/ecc/ECLCG-HITCON-2024
- maple3142 official: https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202024/ECLCG
- Stern's algorithm (1991), J. Stern, "A new identification scheme based on syndrome decoding" — original orthogonal lattice attack on truncated LCG
