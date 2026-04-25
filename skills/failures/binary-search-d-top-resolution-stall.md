---
name: binary-search-d-top-resolution-stall
description: RSA d=top binary search (f = ceil(A/mid))는 mid²/A 정수 산술 한계로 (b-a) ≈ 2·mid²/A에서 stall. 단일 boundary cut 안 됨. m << n + tight initial interval 케이스에서 발생
type: failure
---

## 잘못 접근한 패턴

RSA decryption oracle이 "f·m mod n의 MSB 정보" 알려줄 때, 단순 binary search:

```python
mid = (a+b)//2
f = ceil(A/mid)        # A = 0x67·16^254 (or any conformant boundary)
threshold = ceil(A/f)  # 이상적으로 ≈ mid
if oracle(c * f^e mod n):
    a = max(a, threshold)
else:
    b = min(b, threshold-1)
```

작은 m (e.g., short flag, K~20)에서는 잘 작동. **큰 m (K=103)에서는 stall.**

## 왜 stall하나

Threshold deviation: threshold = mid - mid²/A (정수 산술 round-off)

- For mid ≈ m, mid²/A_top = m²/A_top ≈ 2^(2·log₂(m) - log₂(A))
- (b-a) > 2·mid²/A: threshold이 (a, b) 안에 있음 → narrow 작동
- **(b-a) ≤ 2·mid²/A: threshold ≤ a → hit이 a := max(a, threshold) = a, no narrow → stall**

UMDCTF 2026 case 실측:
- m ≈ 2^886, A_top = 2^1022.69 → mid²/A = 2^750
- 초기 (b-a) = 2^832 → 81 query만에 width=751로 narrowing 후 STUCK FOREVER
- 200+ query 추가해도 width 변화 없음 (실측 검증)

## 잘못된 fix 시도

1. **d=top 대신 작은 d**: A_d 작아짐 → mid²/A 더 커짐 → stall 더 빨리. 더 나쁨.
2. **Bleichenbacher 표준 적용**: m << n이라 Bleichenbacher's si range가 폭발 (2^800+ elements). 표준 increment infeasible.
3. **r-wrap으로 custom threshold**: 단일 정확한 m에서만 hit, narrow 정보 없음.
4. **byte-by-byte recovery**: 각 byte 풀려면 같은 magnitude binary search 필요 → 같은 stall.

## 올바른 fix

**양방향 narrow (Manger 변종)**: 단일 threshold cut이 아니라 **f·[a, b)가 [i·n+A, i·n+B) interval을 양쪽 boundary 다 갖게** 만들어 hit ⟺ m ∈ [hit_lo, hit_hi). 자세한 건 `attack/rsa-msb-byte-oracle-manger-variant`.

핵심 차이:
- **잘못**: `hit ⟺ m ≥ threshold` (단일 cut)
- **옳음**: `hit ⟺ m ∈ [hit_lo, hit_hi)` (interval 안에 들어가는지)

후자는 i (lift count) 다양화 + clean lift 강제로 만들어짐.

## Stall 진단법

이 함정 디버깅:
1. `width_bits` (= (b-a).bit_length()) 가 50+ query에 멈추면 stall 의심
2. 실측: `mid²/A_top`을 계산. (b-a) ≤ 2·mid²/A이면 fundamental stall.
3. 단일 cut 알고리즘 즉시 버리고 양방향 Manger 변종으로.

## 일반화

이 stall은 **integer arithmetic resolution limit**의 일종. f가 integer이고, threshold = A/f은 f가 1 변할 때 A/f² 만큼 변함. f² ≈ A²/mid² → threshold step = mid²/A.

해결: 단일 f에 의존하지 말고 (f, i, ±df) 조합을 sample해서 desired interval을 정확히 만듦.

## 관련

- 성공한 attack: `attack/rsa-msb-byte-oracle-manger-variant`
- 비슷한 정수 산술 함정: `failures/hand-rolled-inverse-edge-cases` (정수 round-off 이슈)
