# Base64
- **출처**: CryptoHack - Introduction
- **난이도**: 10 pts
- **카테고리**: Encoding
- **technique**: hex_to_bytes, base64_encode

## 문제 요약
Hex → bytes → Base64 인코딩하면 플래그.

## 풀이
`bytes.fromhex()` → `base64.b64encode()` 체이닝.

## 플래그
`crypto/Base+64+Encoding+is+Web+Safe/`
