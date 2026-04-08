# Modular Inverting
- **출처**: CryptoHack - Introduction
- **난이도**: 25 pts
- **카테고리**: Mathematics
- **technique**: modular_inverse, fermats_little_theorem

## 문제 요약
3의 mod 13 역원 구하기: 3*d ≡ 1 (mod 13).

## 풀이
- 페르마 소정리: d = 3^(p-2) mod p = 3^11 mod 13 = 9
- Python 3.8+: `pow(3, -1, 13)`
- 확장 유클리드로도 가능

**검증**: 3 * 9 = 27 = 2*13 + 1 ≡ 1 (mod 13) ✓

**인사이트**: RSA 복호화 키 d = e^(-1) mod φ(n) 계산의 기초.

## 답
`9`
