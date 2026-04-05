# Favourite byte
- **출처**: CryptoHack - Introduction
- **난이도**: 20 pts
- **카테고리**: XOR
- **technique**: single_byte_xor_bruteforce

## 문제 요약
단일 바이트 키로 XOR 암호화된 데이터. 키를 모르므로 브루트포스.

## 풀이
0x00~0xFF (256가지) 전수 조사, `crypto{` 패턴 매칭.

**인사이트**: single-byte XOR은 항상 브루트포스 가능 (키 공간 256).

## 플래그
`crypto{0x10_15_my_f4v0ur173_by7e}`
