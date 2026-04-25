---
name: rsa-msb-byte-oracle-manger-variant
description: RSA oracle이 "복호화 결과의 hex 표현이 특정 바이트(예 0x67)로 시작하는지"만 알려줄 때, Manger 스타일로 [mmin, mmax)를 양방향 narrow. 단일 boundary cut binary search는 정수 산술 stall, 양쪽 boundary 활용 + 다양한 i(lift count) 시도가 핵심
type: skill
---

## Oracle 형태

```python
pt = hex(pow(user_ct, d, n))
return pt.startswith("0x67")
```

즉 oracle hit ⟺ `f*m mod n ∈ ⋃_d [0x67·16^(d-2), 0x68·16^(d-2))` (어떤 d에 대해서든 hex가 "0x67"로 시작)

dominant interval은 d=top: `[A, B) = [0x67·16^(n_hex-2), 0x68·16^(n_hex-2))`

## 내가 빠졌던 stall

표준 d=top binary search:
```
mid = (a+b)//2
f = ceil(A/mid)
threshold = ceil(A/f)  # ≈ mid - mid²/A
```

`mid²/A` (≈ 2^750 for our case)가 (b-a)/2와 비슷해지면 **threshold ≤ a**가 되어 hit이 a를 narrow 못 함 → stall.

실측: width 2^832 → 2^751에서 stall, 17 bytes만 복구 후 정지.

## 올바른 접근: Manger 변종 (양방향 narrow)

핵심 idea 4가지:

### 1. 다양한 i (lift count) 시도

f·m mod n = f·m - i·n. 어떤 i에 떨어지냐가 정보. 단순히 i=0 (no wrap)만 쓰지 말고 i ∈ [0, i_max] 다양하게.

```python
i_max = (f_max * mmax) // n + 1
for i in i_list:  # sample 0..i_max
    f_target = (i * n + A) // target_m
    for df in (0, 1, -1, 2, -2, 3, -3):
        f = f_target + df
        ...
```

### 2. Clean lift 강제

f·[mmin, mmax)가 i·n과 (i+1)·n boundary를 가로지르지 않게:

```python
v_lo = f * mmin
v_hi = f * mmax
if not (i*n <= v_lo and v_hi <= (i+1)*n):
    continue  # not clean lift, skip
```

이 강제로 f·m이 정확히 i-th 슬라이스에 떨어지는 게 보장됨.

### 3. 양쪽 boundary 활용 (= 진짜 핵심)

Hit zone이 `[i·n + A, i·n + B)`. v_lo가 i·n + A의 LEFT, v_hi가 RIGHT. 그래서 hit ⟺ m ∈ `[hit_lo, hit_hi)` 양방향 cut:

```python
target_A = i * n + A
target_B = i * n + B
if not (v_lo <= target_A < v_hi):
    continue  # need to straddle A boundary

m_A = (target_A + f - 1) // f  # ceil
if target_B < v_hi:
    m_B_inside = (target_B + f - 1) // f
    hit_lo = max(m_A, mmin)
    hit_hi = min(m_B_inside, mmax)
else:
    hit_lo = max(m_A, mmin)
    hit_hi = mmax
```

이전 시도(single boundary cut)와의 차이: 우리는 단순히 m vs threshold 1bit 갈랐는데, 양쪽 boundary 쓰면 **hit ⟺ m이 [hit_lo, hit_hi) 안에 있음** 식으로 정확한 interval 줌.

### 4. Balance scoring (선택)

hit zone width가 (mmax - mmin)/2에 가까운 f를 선호해 narrowing 절반에 가깝게:

```python
hit_width = hit_hi - hit_lo
bal = abs(2 * hit_width - width)
if best is None or bal < best[0]:
    best = (bal, f, i, hit_lo, hit_hi)
```

## Update 규칙

```python
if oracle(ct * pow(f, e, n) % n):
    new_a, new_b = hit_lo, hit_hi  # m이 hit zone 안
else:
    # m이 [a, hit_lo) 또는 [hit_hi, b) 둘 중 큰 쪽
    if (hit_lo - a) >= (b - hit_hi):
        new_a, new_b = a, hit_lo
    else:
        new_a, new_b = hit_hi, b
```

## 부수 가속: ASCII tighten

flag content가 printable ASCII (0x20-0x7e)면 매 step마다 `[a, b)`를 ASCII pattern과 intersect:

```python
def intersect_with_S(a, b, n_bytes, prefix_bytes, suffix_byte):
    # smallest_in_S_ge(a, ...) and largest_in_S_lt(b, ...)
    # walks bytes MSB-first; each position has byte_range (lo, hi)
```

대략 100 step당 5-10 bit 추가 narrow.

## 성능

UMDCTF 2026 no-brainrot-allowed (1023-bit n, K=103 content):
- 로컬 sim: 692 query, ~10초
- 서버 (실측): 671 query, ~196초
- ASCII tighten 없으면 ~830 query

## 적용 조건

1. RSA oracle이 binary "복호화 결과의 hex가 X로 시작" 형태
2. Known prefix 또는 [m_low, m_high] 추정 가능 (이 챌린지: cluster + UMDCTF{ prefix → K=103)
3. Public exponent 와 modulus 알려짐 (chosen ciphertext 가능)

## Reference

- Manger 2001 OAEP CCA: https://archiv.infsec.ethz.ch/education/fs08/secsem/manger01.pdf
- DownUnderCTF 2022 rsa-interval-oracle 시리즈 (구조적으로 유사한 챌린지들): https://github.com/DownUnderCTF/Challenges_2022_Public/tree/main/crypto

## 관련 챌린지

- UMDCTF 2026 no-brainrot-allowed: 0x67 ('g') byte oracle, K=103, Manger 변종으로 풀이
- DownUnderCTF 2022 rsa-interval-oracle-ii: 384-bit RSA, single interval, Manger's attack
