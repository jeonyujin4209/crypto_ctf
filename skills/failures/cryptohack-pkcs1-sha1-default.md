---
name: cryptohack-pkcs1-sha1-default
description: CryptoHack의 pkcs1 라이브러리는 SHA-1이 기본. 문제에서 명시 없으면 SHA-256 쓰지 말것
type: failure
---

# CryptoHack pkcs1 라이브러리 SHA-1 기본

## 실패 패턴
CryptoHack 문제에서 제공되는 `pkcs1` 라이브러리로 서명/검증 시:
- **기본 hash = SHA-1** (PKCS#1 v1.5 signature)
- 다른 라이브러리(pycryptodome 등)는 SHA-256 기본인 경우가 많아 혼동

AI가 SHA-256 가정하고 서명 포맷 만들다가 검증 실패 → "서명이 왜 안 맞지?" 무한 디버그.

## 확인 방법
```python
import pkcs1
help(pkcs1.emsa_pkcs1_v15.encode)  # digest parameter default 확인
```

또는 DigestInfo prefix로 구분:
- SHA-1:   `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14`
- SHA-256: `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`

Length도 다름 (SHA-1 = 20 bytes, SHA-256 = 32 bytes).

## 교훈
- CryptoHack 문제 → 라이브러리 소스 확인 먼저
- 서명 검증 실패 시 제일 먼저 hash algorithm 의심
- 다른 플랫폼에도 동일 패턴 가능 (pyca/cryptography vs pycryptodome 기본 다를 수 있음)

## 관련
- `attack/hastad-small-message-broadcast` — RSA small message
