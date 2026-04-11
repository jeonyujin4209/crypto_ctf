# Pohlig-Hellman on Chosen Smooth Group: p_smooth Must Exceed p_orig

## 유형
Diffie-Hellman MITM에서 서버가 **static private key** `b`를 쓰고, 공격자가
custom `(p, g, A)`를 보내 `B' = A^b mod p_smooth`를 받아 Pohlig-Hellman으로
`b`를 복구하는 시나리오.

## Trigger 패턴
- 서버가 매 연결마다 같은 `b`를 사용 (static long-term key)
- 공격자가 handshake 파라미터 `(p, g, A)`를 자유롭게 선택 가능
- 원본 group이 큰 safe prime (예: 1024~2048-bit)
- B-smooth prime을 만들어 Pohlig-Hellman으로 dlog 시도
- dlog는 *성공*하지만 `pow(g_orig, b_recovered, p_orig) != B_bob` 로 최종 검증 실패

## 왜 못 풀었나 (A)

### 시도 1: p_smooth를 "적당히 크게" 만들기
`make_smooth_prime(min_bits=800)` 같은 고정값. 800~1024-bit smooth prime을
빨리 생성하는 데에만 집중. Pohlig-Hellman 자체는 몇 초 안에 끝남.

복구한 `b_recovered`가 그럴듯하게 나와서 (음수 아님, 큰 수) 성공한 줄 알고
AES 복호화 시도 → 쓰레기 plaintext. 검증식 `pow(2, b_recovered, p_orig) == B_bob`
찍어보면 `False`.

### 진짜 원인
Pohlig-Hellman으로 dlog를 풀면 답은 **`b mod ord_{p_smooth}(g)`** 이다.
`g`가 `Z_{p_smooth}*`에서 primitive root면 `ord = p_smooth - 1`.

서버의 실제 `b`는 `[1, p_orig - 1)` 범위의 random 값이다. 따라서:
- `p_smooth - 1 > b` 이면 `b_recovered == b` (성공)
- `p_smooth - 1 < b` 이면 `b_recovered = b mod (p_smooth - 1)` 로 **상위 비트 truncation**
- 경계에 있는 경우 우연히 맞을 수도 있지만 거의 항상 실패

1536-bit `p_orig`에서 `b`는 기대값 기준 ~1535-bit. 여기에 815-bit `p_smooth`
쓰면 하위 815-bit만 남고 나머지는 날아감.

## 어떻게 해결했나 (B)

### 해법: `p_smooth > p_orig` 보장
`make_smooth_prime(min_bits=p_orig.bit_length() + 16)` 로 여유 있게 잡는다.

```python
p_smooth = make_smooth_prime(min_bits=p_orig.bit_length() + 16)
# verify: p_smooth - 1 >= p_orig - 1 이므로 b < ord(g) 보장
```

### Smooth prime 생성 비용
1552-bit smooth prime은 800-bit보다 오래 걸리지만 여전히 합리적:
- `n = 2 * 3 * 5 * 7 * ... * q` 누적, `bit_length() >= min_bits` 까지
- `n + 1` primality 확인 (랜덤성 주려고 small prime 몇 개 추가 곱)
- 2가 primitive root인지 `factorint(p-1)`의 각 factor에 대해 체크

Pohlig-Hellman은 가장 큰 factor의 `O(sqrt)` 에 의존. 전체 크기가 아니라
**largest prime factor의 크기**가 관건이므로 1552-bit라도 각 factor가 20~40-bit
수준이면 여전히 수 초 안에 끝남.

### 검증식을 반드시 넣기
```python
assert pow(g_orig, b_recovered, p_orig) == B_bob, \
    "recovered b does not match eavesdropped B; smooth prime likely too small"
```
이 assert가 없으면 truncation을 감지 못 하고 엉뚱한 AES 복호화로 시간 낭비.

## 대안: CRT 조합
한 방에 큰 smooth prime을 못 만들 상황이면, 여러 작은 smooth prime들로 나눠:
1. `p_1, p_2, ..., p_k` 생성 (각각 smooth, 서로 다른 `ord` factor)
2. 각각 `b_i = b mod ord_i` 복구
3. CRT로 `b mod lcm(ord_1, ..., ord_k)` 결합
4. `lcm > p_orig` 되도록 충분히 모음

단, 각 쿼리마다 서버에 reconnect 필요. 서버가 `b`를 진짜 static으로 유지한다는
전제가 있어야 함.

## 적용 범위
- Static-key DH MITM challenges
- 일반적으로 "Pohlig-Hellman으로 chosen-group dlog" 쓰는 모든 시나리오
- 예: custom curve 공격에서도 `#E_smooth > n_orig` 조건 비슷하게 성립해야 함
- 하위 비트만 뽑으려는 의도가 있는 것이 아니라면 **항상 `ord ≥ secret` 확인**

## 핵심 교훈
**Pohlig-Hellman은 `secret mod ord(base)` 만 돌려준다.** 완전한 `secret`을 원하면
`ord(base) ≥ secret` 이 필수 전제. chosen-prime 공격에서 이걸 까먹으면 dlog가
"성공"해도 결과는 쓸모없는 하위 비트 덩어리.

공격 전 한 줄 체크:
```python
assert (p_smooth - 1) > p_orig, "smooth group too small — b will be truncated"
```

## 출처
- CryptoHack: Static Client (Diffie-Hellman / Man In The Middle)
  - `p_orig = 1536-bit`, 초기 `min_bits=800` 세팅으로 dlog는 되지만 검증 실패
  - `min_bits=p_orig.bit_length() + 16` 으로 수정 후 즉시 풀림
- Reference: Pohlig-Hellman 원논문은 "full order" 가정, chosen-prime MITM 응용에서 이 조건이 깨질 수 있음
