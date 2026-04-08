# XOR Properties
- **출처**: CryptoHack - Introduction
- **난이도**: 15 pts
- **카테고리**: XOR
- **technique**: xor_properties, key_recovery_chain

## 문제 요약
KEY1, KEY2^KEY1, KEY2^KEY3, FLAG^KEY1^KEY3^KEY2가 주어짐. XOR 성질로 FLAG 복원.

## 풀이
1. KEY2 = (KEY2^KEY1) ^ KEY1
2. KEY3 = (KEY2^KEY3) ^ KEY2
3. FLAG = (FLAG^K1^K3^K2) ^ K1 ^ K2 ^ K3

**핵심 성질**: 교환법칙, 결합법칙, 자기역원(A⊕A=0)

## 플래그
`crypto{x0r_i5_ass0c1at1v3}`
