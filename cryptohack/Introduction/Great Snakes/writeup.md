# Great Snakes
- **출처**: CryptoHack - Introduction
- **난이도**: 3 pts
- **카테고리**: General
- **technique**: single_byte_xor

## 문제 요약
정수 배열을 고정 키 0x32로 XOR하면 플래그.

## 풀이
`chr(o ^ 0x32)` 로 각 바이트 복호화.

## 플래그
`crypto{z3n_0f_pyth0n}`
