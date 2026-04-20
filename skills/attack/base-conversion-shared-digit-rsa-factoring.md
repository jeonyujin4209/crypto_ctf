---
name: base-conversion-shared-digit-rsa-factoring
description: p의 k진수 digit이 q의 십진수 digit과 동일한 RSA 구조 → MSB-first greedy digit 탐색으로 O(L) 인수분해
type: attack
---

## 상황

```python
p = random.getrandbits(256)          # 256-bit 랜덤 소수
q = int(gmpy2.digits(p, k))          # p를 k진수로 변환 → 10진수로 해석
```

q의 10진 digit = p의 k진 digit (모두 {0,...,k-1}). 이 구조가 p, q를 연결해 RSA를 취약하게 만든다.

## 핵심 관찰

digit d_i를 공유하므로:

```
p = Σ d_i · k^i
q = Σ d_i · 10^i        (같은 d_i, 다른 밑)
```

p가 L자리 k진수면 q도 L자리 10진수. d_i ∈ {0,...,k-1}.

## 공격: MSB-first greedy digit search

### 왜 O(L)인가?

자릿수를 MSB부터 하나씩 결정할 때, 후보 digit d ∈ {0,...,k-1}의 유효성 조건:

```
0 ≤ r = n - p_high·q_high ≤ UB
```

여기서 `UB = p_high·q_rem_max + q_high·p_rem_max + p_rem_max·q_rem_max`  
(나머지 자리가 모두 k-1일 때의 최댓값)

**UB ≈ step** (d가 1 증가할 때 r의 감소량)이므로 세 구간이 [0, 3·step]을 겹치지 않고 분할 → 각 step에서 유효 digit은 정확히 1개.

### 코드

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def try_solve(n, L, base_p=3):
    """base_p: p의 진수 (q는 항상 10진수 해석)"""
    pow_p  = [gmpy2.mpz(base_p) ** i for i in range(L + 1)]
    pow_q  = [gmpy2.mpz(10) ** i     for i in range(L + 1)]
    max_d  = base_p - 1  # digit 최댓값

    # DFS: (pos, p_high, q_high)
    stack = [(L - 1, gmpy2.mpz(0), gmpy2.mpz(0))]

    while stack:
        pos, p_h, q_h = stack.pop()

        for d in range(max_d, -1, -1):
            if pos == L - 1 and d == 0:
                continue  # 최상위 자리 0 불가

            new_p = p_h + d * pow_p[pos]
            new_q = q_h + d * pow_q[pos]
            new_r = n - new_p * new_q

            if new_r < 0:
                continue

            if pos == 0:
                if new_r == 0:
                    return int(new_p), int(new_q)
            else:
                p_rem_max = pow_p[pos] - 1
                q_rem_max = max_d * (pow_q[pos] - 1) // (10 - 1)  # 모든 digit = max_d
                UB = new_p * q_rem_max + new_q * p_rem_max + p_rem_max * q_rem_max
                if new_r <= UB:
                    stack.append((pos - 1, new_p, new_q))

    return None, None


def solve(n, e, c, base_p=3):
    import math
    L_est = int(math.log(int(n)) / math.log(base_p * 10)) + 1

    for L in range(L_est - 2, L_est + 3):
        result = try_solve(n, L, base_p)
        if result and result[0] is not None:
            p, q = result
            assert p * q == n
            phi = (p - 1) * (q - 1)
            d_rsa = int(gmpy2.invert(e, phi))
            m = pow(int(c), d_rsa, int(n))
            return long_to_bytes(m)
    return None
```

## L 추정

`p ∈ [base_p^{L-1}, base_p^L)`, `q ∈ [10^{L-1}, 10^L)` 이므로 `n ∈ [(base_p·10)^{L-1}, (base_p·10)^L)`.

```python
L_est = int(math.log(int(n)) / math.log(base_p * 10)) + 1
# base_p=3이면 log_30(n) + 1
```

±2 범위로 탐색하면 항상 찾을 수 있음.

## 복잡도

- L ≈ 256·log(2)/log(base_p) 자리 (base_p=3이면 ≈162)
- 각 step에서 O(1) digit 선택 → 전체 O(L) big-int 연산
- 실행 시간: < 1초

## 변형

- base_p ≠ 3 (예: base 2, 4, 16)도 동일하게 적용. `max_d = base_p - 1`, `q_rem_max` 공식만 조정.
- p, q 역할이 바뀐 경우 (`p = int(digits(q, k))`)도 동일 — 변수명 교환.
