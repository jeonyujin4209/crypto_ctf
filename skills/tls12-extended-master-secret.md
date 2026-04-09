# TLS 1.2 Decryption: Extended Master Secret Trap

## 유형
TLS 1.2 pcap 복호화 (RSA key exchange 또는 (EC)DHE)

## Trigger 패턴
- TLS 1.2 pcap + private key (RSA) 또는 premaster secret 주어짐
- 표준 procedure로 master_secret 유도 → AEAD 복호화 시 `InvalidTag` / decryption error
- ChangeCipherSpec 이후 첫 Finished 메시지부터 복호화 실패

## 왜 못 풀었나 (A)

### 시도 1: 표준 PRF 적용
RFC 5246 그대로:
```python
master_secret = PRF(pms, "master secret", client_random + server_random, 48)
```
→ AEAD InvalidTag. PMS는 RSA decrypt로 정확히 추출했고, randoms도 pcap에서 정확.

### 시도 2: 다른 cipher suite, 다른 PRF hash 시도
SHA-256 vs SHA-384 바꿔봄, key derivation label 오타 확인 → 다 정상. 여전히 fail.

### 시도 3: nonce 구성 의심
TLS 1.2 AEAD는 `salt(4) || explicit_nonce(8)` 또는 `salt XOR seq` (RFC 7905). 둘 다 시도 → fail.

### 진짜 원인
**ClientHello extension에 Extended Master Secret (type 0x17)이 있었음.** RFC 7627. 이게 켜져 있으면 master_secret 유도식이 완전히 바뀐다. 이걸 모르면 영원히 못 풀린다.

## 어떻게 해결했나 (B)

### 1. Extension 0x17 감지
ClientHello / ServerHello extensions 파싱해서 type `0x0017` 존재 여부 확인. 둘 다 있어야 EMS active.

```python
def has_ems(hello_extensions: bytes) -> bool:
    i = 0
    while i + 4 <= len(hello_extensions):
        ext_type = int.from_bytes(hello_extensions[i:i+2], 'big')
        ext_len = int.from_bytes(hello_extensions[i+2:i+4], 'big')
        if ext_type == 0x0017:
            return True
        i += 4 + ext_len
    return False
```

### 2. session_hash 계산
EMS의 master_secret은 random이 아니라 **handshake transcript hash**를 씀:

```
session_hash = Hash(ClientHello || ServerHello || Certificate || ServerKeyExchange? || ServerHelloDone || ClientKeyExchange)
```
- Hash는 cipher suite의 PRF hash (보통 SHA-256, SHA-384)
- **ClientKeyExchange까지 포함, ChangeCipherSpec 이전까지**
- 각 메시지는 record layer 헤더 제외, **handshake 헤더(4 byte) 포함**

### 3. EMS master_secret 유도
```python
master_secret = PRF(pms, "extended master secret", session_hash, 48)
```
**`client_random || server_random`이 아니라 `session_hash`를 seed로 사용**.

이후 key_block 유도, AEAD 복호화는 동일.

### 핵심 디버깅 단서
- `InvalidTag`인데 PMS / randoms / cipher suite 모두 확인된 경우 → **즉시 EMS 의심**
- pcap에서 ClientHello extensions hex dump 떠서 `00 17 00 00` 검색

## 적용 범위
- TLS 1.2 pcap 복호화 challenge 전반
- 실제 TLS 1.2 트래픽 분석 (현대 브라우저는 거의 EMS 사용)
- TLS 1.3은 무관 (key schedule이 완전히 다름)

## Bonus: TLS 1.3 비교
TLS 1.3은 EMS 개념이 없고, 처음부터 `Hash(ClientHello || ServerHello)` 기반 derived secret을 사용. SSLKEYLOGFILE이 있으면 `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0` 등을 직접 읽어서 traffic key 유도.

## 출처
- CryptoHack: Decrypting TLS 1.2 (30pts, Crypto on the Web / TLS Part 1)
- RFC 7627 (Extended Master Secret)
