# Modular Arithmetic 2
- **출처**: CryptoHack - Introduction
- **난이도**: 20 pts
- **카테고리**: Mathematics
- **technique**: fermats_little_theorem

## 문제 요약
273246787654^65536 mod 65537 계산.

## 풀이
페르마 소정리: p가 소수이고 gcd(a,p)=1이면 a^(p-1) ≡ 1 (mod p).
65537은 소수, 65536 = 65537-1 → 답은 1. 계산기 불필요.

**인사이트**: RSA에서 e=65537이 자주 쓰이는 이유와 연결됨.

## 답
`1`
