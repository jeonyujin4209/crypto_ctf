# SSH Keys
- **출처**: CryptoHack - Introduction
- **난이도**: 35 pts
- **카테고리**: Data Formats
- **technique**: ssh_pubkey_parsing

## 문제 요약
SSH 공개키(ssh-rsa 포맷)에서 modulus(n) 추출.

## 풀이
ssh-rsa 공개키는 base64 인코딩된 바이너리: `[type_len][type][e_len][e][n_len][n]`
각 필드는 4바이트 빅엔디안 길이 접두사. `struct.unpack('>I', ...)` 로 파싱.

## 답
`3931406272922523448...48243492909`
