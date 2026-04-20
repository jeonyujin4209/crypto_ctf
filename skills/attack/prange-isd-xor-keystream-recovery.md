---
name: prange-isd-xor-keystream-recovery
description: 여러 AES-CTR(혹은 stream cipher) 인스턴스를 XOR한 구조에서 known-plaintext로 syndrome decoding(Prange ISD)으로 키스트림 복구
type: skill
---

## 상황

```python
# 각 인스턴스가 key의 1바이트만 사용 (나머지는 \x00 패딩)
aes_i = AES.new(key=key[i:i+1] + b'\x00'*15, mode=CTR, counter=...)
# 평문을 n개 인스턴스로 연속 암호화
ciphertext = aes_0(aes_1(...(aes_n(plaintext))))
```

CTR 모드 XOR 연속 = `combined_ks = XOR of ks[key[i]] for i in 0..n-1`.

known plaintext 존재 → combined_ks 일부 알고 있음 → 키 복구?

## 핵심 관찰

`combined_ks = XOR of ks[b] for b in S`

- **S** = key에서 **홀수 번** 등장하는 바이트 값의 집합 (중복 짝수 → 상쇄)
- S ⊆ {0..255}, |S| ≤ n (n개 키 바이트 중 최대 n개 distinct)
- S만 복구하면 전체 키스트림(플래그 범위 포함) 재현 가능

## 공격: Syndrome Decoding → Prange ISD

### 1. 시스템 구성

```python
# M: (8*known_bytes, 256) GF(2) 행렬 — 각 열 b는 ks[b]의 알려진 위치 bit
M = np.zeros((8 * len(known_bytes), 256), dtype=np.uint8)
for b in range(256):
    M[:, b] = np.unpackbits(ks[b][known_positions])

T = np.unpackbits(known_combined_ks)  # 타깃 벡터
# 구하는 것: M * x = T (GF2), x ∈ {0,1}^256, wt(x) ≤ n
```

### 2. Prange ISD 루프

```python
def prange_isd(M, T, t=16, max_iter=5000):
    m, n = M.shape  # (208, 256) 예시
    for _ in range(max_iter):
        perm = np.random.permutation(n)
        aug = np.hstack([M[:, perm].copy(), T.reshape(-1, 1)]).astype(np.int8)

        pivot_row, pivot_cols = 0, []
        for col in range(n):
            rows = np.nonzero(aug[pivot_row:, col])[0]
            if not len(rows): continue
            pivot = pivot_row + rows[0]
            aug[[pivot_row, pivot]] = aug[[pivot, pivot_row]]
            mask = aug[:, col].copy(); mask[pivot_row] = 0
            aug[np.where(mask)[0]] ^= aug[pivot_row]
            pivot_cols.append(col); pivot_row += 1
            if pivot_row == m: break

        if pivot_row < m: continue
        syn = aug[:, n].astype(np.uint8)
        if syn.sum() <= t:           # 성공 조건
            x = np.zeros(n, dtype=np.uint8)
            for i, col in enumerate(pivot_cols):
                if syn[i]: x[col] = 1
            x_orig = np.zeros(n, dtype=np.uint8)
            x_orig[perm] = x
            return x_orig
    return None
```

### 3. 플래그 복호화

```python
x = prange_isd(M, T_bits, t=n_key_bytes)
S = [b for b in range(256) if x[b]]
combined_ks_full = np.zeros(total_len, dtype=np.uint8)
for b in S:
    combined_ks_full ^= ks_full[b]
flag = bytes(c ^ k for c, k in zip(ciphertext, combined_ks_full))
```

## 수렴 분석

| 파라미터 | 예시 값 | 수렴률/iter |
|---------|--------|------------|
| m (constraint bits) | 208 (26바이트) | — |
| n (possible values) | 256 | — |
| t (target weight) | ≤ 16 | — |
| **P(성공/iter)** | C(208,16)/C(256,16) | **≈ 5%** |
| **기대 반복 수** | — | **≈ 20회** |

## 사전 작업: 소규모 S 탐색 (빠른 MITM)

ISD 전에 먼저 소규모 S 체크:

```python
# |S|=1: ks[b][:26] == T_bytes 체크
# |S|=2: pair_table[ks[a]^ks[b]] == T_bytes
# |S|=4: pair_table MITM (32640^2 / dict_lookup ≈ 즉시)
pair_table = {bytes(ks26[a]^ks26[b]): (a,b) for a in range(256) for b in range(a+1, 256)}
for c in range(256):
    for d in range(c+1, 256):
        needed = bytes(x^y for x,y in zip(T_bytes, ks26[c]^ks26[d]))
        if needed in pair_table:
            a, b = pair_table[needed]
            if len({a,b,c,d}) == 4:
                S = {a, b, c, d}; break
```

## 적용 조건 체크리스트

1. ☐ n개 stream cipher/CTR 인스턴스를 XOR 연산으로 결합?
2. ☐ 각 인스턴스 키 엔트로피가 ≤ 1바이트 (256가지)?
3. ☐ 알려진 평문이 8*(n_key_bytes)비트 이상? (constraint 충분)
4. ☐ 키 바이트 수 n ≤ ~20 (weight ≤ 20이면 ISD 빠름)?

→ 모두 예 → Prange ISD 적용 가능

## 주의사항

- **ISD는 확률적**: 간혹 false-positive (weight≤t지만 wrong coset representative). verify 필수.
- 같은 T를 만족하는 S가 2^(n-m)개 있을 수 있음 → weight 조건이 unique 보장에 중요.
- **flag format check로 검증**: 복호화 결과가 알파벳 형태인지 확인.
- `t` 값은 실제 키 바이트 수(n)로 설정. 너무 크면 false-positive 증가.
