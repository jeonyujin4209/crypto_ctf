---
name: hastad-small-message-broadcast
description: RSA e가 크더라도 메시지가 작으면 e개 미만의 ciphertext로 Hastad broadcast attack 가능
type: skill
---

## 상황

RSA e가 큰데 (예: e=17) 같은 평문 m을 서로 다른 n_i로 암호화한 ciphertext c_i를 여러 개 확보.
표준 Hastad는 e개 ciphertext 필요하지만, **m이 n보다 훨씬 작으면 더 적은 수로 가능**.

## 핵심 조건

k개 ciphertext로 성공하려면:

```
m^e < n_1 * n_2 * ... * n_k
```

즉 `k > e * log(m) / log(n)`. m이 256-bit이고 n이 1024-bit이면:

- e=17 → 표준: 17개 필요 → **실제: ceil(17 * 256/1024) = 5개면 충분!**

## 공격 절차

```python
from gmpy2 import iroot
from functools import reduce

def crt(residues, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for r_i, m_i in zip(residues, moduli):
        Mi = M // m_i
        yi = pow(Mi, -1, m_i)
        x += r_i * Mi * yi
    return x % M

# c_i = m^e mod n_i, k개 수집
C = crt(ciphertexts, moduli)   # m^e < product(n_i) → CRT가 m^e 정확히 복원
m, is_perfect = iroot(C, e)    # 정수 e-th root
assert is_perfect
```

## n을 모를 때: 1-send 복원

known plaintext m_known 하나로 n 복원:

```python
# c = m_known^e mod n → m_known^e - c = k * n
# m_known = 2^61 (e=17일 때 m^17 ≈ 2^1037, n ≈ 2^1024 → k ≈ 2^13)
kn = m_known**e - c_known
for k in range(kn >> 1024, (kn >> 1022) + 2):
    if kn % k == 0:
        n_cand = kn // k
        if 1022 <= n_cand.bit_length() <= 1024 and n_cand % 2 == 1:
            # 후보 발견 — c_backup < n_cand 등으로 검증
```

## 실전 예시 (Key Backup Service 1)

- e=17, ms=256-bit, n=1024-bit, 17 calls
- 5개 키 × (pkey + send + backup) + flag = 16 calls
- CRT(5개 backup) → ms^17 → iroot(17) → master_secret → AES 복호화
