# Encoding Challenge
- **출처**: CryptoHack - Introduction
- **난이도**: 40 pts
- **카테고리**: Encoding
- **technique**: multi_encoding_auto_decode, pwntools_json_socket

## 문제 요약
서버가 base64/hex/rot13/bigint/utf-8 중 랜덤 인코딩을 100라운드 보냄. 전부 디코딩하면 플래그.

## 풀이
`type` 필드로 분기하여 자동 디코딩 루프.

| type | 디코딩 |
|------|--------|
| base64 | `base64.b64decode()` |
| hex | `bytes.fromhex()` |
| rot13 | `codecs.decode(s, 'rot_13')` |
| bigint | `long_to_bytes(int(s, 16))` |
| utf-8 | `''.join(chr(c) for c in arr)` |

## 플래그
`crypto{3nc0d3_d3c0d3_3nc0d3}`
