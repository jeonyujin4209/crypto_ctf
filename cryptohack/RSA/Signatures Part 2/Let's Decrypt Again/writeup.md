# Let's Decrypt Again

- **Category**: RSA / Signatures Part 2
- **Points**: 150
- **Server**: socket.cryptohack.org:13394

## Challenge

SIGNATURE가 고정. N(합성수)을 설정하고, 3개의 서로 다른 메시지 패턴에 대해 각각 e를 제공.
pow(SIGNATURE, e_i, N) == emsa_pkcs1_v15.encode(msg_i) 성립 시 share 획득. 3개 XOR → FLAG.

## 실패 기록

### 시도 1: smooth prime p, N = p^2, p-adic DLP
- p-1이 smooth한 ~386비트 소수를 랜덤 생성 → N = p^2
- **실패**: smooth prime 생성 300,000회 반복 → Lightsail(512MB) 메모리/시간 초과 kill

### 시도 2: emsa_pkcs1_v15 SHA-256 vs SHA-1
- 커스텀 SHA-256 인코딩 사용 → 서버는 `pkcs1` 라이브러리 기본 SHA-1
- **실패**: 해시 불일치 `Invalid signature`
- **교훈**: `from pkcs1 import emsa_pkcs1_v15` 필수

## 최종 풀이: N = 41^144

핵심 발상: smooth prime을 **찾을** 필요 없이, **작은 소수의 거듭제곱**을 N으로 사용.

- SIGNATURE mod 41 = 12 (primitive root mod 41 확인)
- N = 41^144 = 772 bits > 768 bits (digest 크기)
- phi(N) = 40 * 41^143 = 2^3 * 5 * 41^143 (극도로 smooth)
- sympy `discrete_log`으로 Pohlig-Hellman + Hensel lifting
- **장점**: smooth prime 생성 불필요, O(초) 실행

### 메시지 패턴
- Pattern 0: `This is a test...for a fake signature.`
- Pattern 1: `My name is Alice and I own CryptoHack.org`
- Pattern 2: Valid Bitcoin address (`1111111111111111111114oLvT2`)
