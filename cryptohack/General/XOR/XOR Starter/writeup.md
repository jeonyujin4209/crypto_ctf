# XOR Starter
- **출처**: CryptoHack - Introduction
- **난이도**: 10 pts
- **카테고리**: XOR
- **technique**: single_byte_xor

## 문제 요약
문자열 "label"의 각 문자를 정수 13과 XOR.

## 풀이
`chr(ord(c) ^ 13)` 로 각 문자 변환.

## 플래그
`crypto{aloha}`
