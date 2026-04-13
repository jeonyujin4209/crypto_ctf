---
name: rsa-last-byte-oracle-binary-search
description: RSA oracle이 "복호화 결과 마지막 바이트 == X" 인지만 알려줄 때, 고정점 승수(fixed-point multiplier)로 overflow를 감지해 binary search로 m 전체를 복구하는 패턴
type: skill
---

## 내가 틀린 방향

"각 바이트를 직접 열거: f * m_byte ≡ 0x2e (mod 256) 인 f를 찾으면 m_byte 복구"
→ n으로 mod 후 lower byte에 영향을 주는 wrapping을 무시했음.
→ 256 쿼리마다 1바이트 복구처럼 보이지만, 실제로 s*m mod n의 last byte는 s, m의 last byte만으로 결정되지 않음 (carry 없이 순수 mod 256으로 계산되긴 하나, overflow 분기가 핵심 정보임을 놓침).

## 올바른 핵심 아이디어

Oracle: `send(c')` → "nice" iff `decrypt(c')[-1] == '.'` (0x2e)

**전제: 평문 m 자체가 0x2e로 끝난다** (메시지가 마침표로 끝나는 경우).

### Fixed-point 승수 0x81의 성질

```
0x81 * 0x2e mod 256 = 129 * 46 mod 256 = 5934 mod 256 = 46 = 0x2e
```

즉 0x81은 0x2e의 **고정점(fixed point)**: 곱해도 last byte가 0x2e로 유지됨.

### Overflow 감지

s ≡ 0x81 (mod 256) 인 s를 골라 `ct * s^e mod n` 을 서버에 보내면:

| 경우 | s*m mod n | last byte | oracle |
|------|-----------|-----------|--------|
| s*m < n (overflow 없음) | s*m | `0x81 * 0x2e mod 256 = 0x2e` | **True** |
| s*m ≥ n (overflow 1회) | s*m − n | `(0x2e − n_last) mod 256 ≠ 0x2e` (n은 홀수) | **False** |

→ **oracle True ↔ s*m < n ↔ m < n/s**

### Binary Search

```python
lo, hi = 0, n - 1
while hi - lo > 1:
    mid = (lo + hi) // 2

    # s ≈ ceil(n/mid), 끝 바이트를 0x81로 맞춤
    s = (n + mid - 1) // mid
    s += (0x81 - s % 256) % 256

    t = (n - 1) // s   # largest m with s*m < n

    if srv.oracle(ct * pow(s, e, n) % n, n):
        hi = t          # oracle True → m ≤ t
    else:
        lo = t + 1      # oracle False → m ≥ t+1
```

- 총 쿼리 수: ~`n.bit_length()` (2048-bit RSA → ~2048 쿼리)
- 각 쿼리로 interval을 대략 절반으로 줄임

## 적용 조건

1. **m이 마침표(0x2e)로 끝나야 함** — 고정점 성질 필요
   - 만약 다른 바이트 X로 끝난다면: X * s_last ≡ X (mod 256) 인 s_last 선택
   - X * s_last ≡ X (mod 256) ↔ X(s_last − 1) ≡ 0 (mod 256)
   - X가 홀수면: s_last ≡ 1 (mod 256/gcd(X, 256)) 인 값 사용
2. n은 홀수 (RSA 기본 조건) → overflow 시 last byte 변함
3. s*m이 2n을 넘지 않아야 함 → flag가 충분히 작으면 (< n/2) 자동 만족

## 왜 Parity Oracle과 다른가

| 비교 | Parity Oracle | Last-Byte Oracle (이 공격) |
|------|--------------|--------------------------|
| 승수 | 2^e (last bit 변화) | s ≡ 0x81 (last byte 고정점) |
| 감지 | m*2 mod n의 홀짝 | s*m mod n의 last byte |
| 원리 | n이 홀수 → overflow 시 LSB flip | m_last 고정점 → overflow 시 last byte 변화 |

본질은 같음: **overflow 감지 → binary search**.

## 관련 챌린지

- Calm Down (HKCERT CTF 2020): 2048-bit RSA, oracle = last byte == '.'
