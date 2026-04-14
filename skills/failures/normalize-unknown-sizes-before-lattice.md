---
name: normalize-unknown-sizes-before-lattice
description: 힌트 방정식에 small unknown 여러 개 있을 때 dominant known 항으로 정규화해서 크기 분석 먼저. 안 그러면 사라지는 unknown도 격자에 넣는 실수 범함
type: failure
---

## 실수 패턴

여러 small unknown (c, d, R1, R2 등)이 있는 힌트 방정식에서 모든 unknown을 격자에 넣으려 했다. 그 중 일부는 dominant known term으로 나누면 O(1)이 되어 사라지는데도 대칭적으로 취급했다.

**1337crypt v2 구체 사례:**

방정식 전개 후 naive p 추정:
```
p_approx = (y - a² - b²·H) / (2ab)
```
에러가 O(2^1338)이라 ±5 탐색이 당연히 실패. 그런데 A=2^338·a+R1, B=2^338·b+R2 치환으로 4변수 격자를 구상하다 막혔다.

## 올바른 접근

**Step 1: dominant known 항으로 정규화**

방정식 전체를 가장 큰 known 항 (예: 2ab)으로 나눈다.

**Step 2: 항별 비트 크기 분석표 작성**

| 항 | 정규화 후 비트 | 처리 |
|---|---|---|
| p | 1337 | 타겟 |
| b²D/(2ab) | ~2674 | known, 빼면 됨 |
| 2^(-l)·(D/a)·d | ~1337 | **unknown, 격자에 넣기** |
| c 관련 항 | **O(1)** | **에러 k에 흡수** |

→ 살아남는 unknown은 d 하나 (338비트). c는 버린다.

**Step 3: 두 방정식으로 dominant unknown 소거**

d를 구하려면 p를 먼저 소거 (반대 방향이 아님):

```
t1 - s1·d1 - k1 = t2 - s2·d2 - k2
⟹ t1 - t2 = s1·d1 - s2·d2 + k
```

여기서 `t_j = y_j - b_j²D/(2a_j·b_j)`, `s_j = 2^(-l)·D/a_j` (모두 known)

**Step 4: 3×3 LLL**

```
[s1    1   0]
[s2    0   1]
[t1-t2  0   0]
```

short vector = (k, -d1, d2). 4변수 격자 불필요.

**Step 5: p 복구**

d를 얻은 후:
```
p ≈ (y - (b² + 2·2^(-l)·b·d)·D) / (2ab)
```
오차가 수 비트 이내 → ±작은 범위 탐색 + D-p² 제곱수 체크.

**Why:** 정규화 없이 격자를 구성하면 실제로는 O(1)인 unknown을 독립 변수로 넣어서 격자 차원만 늘어나고 short vector를 못 찾는다.

**How to apply:** 힌트 방정식에 small unknown이 3개 이상이면 dominant known term으로 나눠서 항별 크기 계산 먼저. O(1) 이하인 unknown은 격자에서 제외하고 에러로 처리.
