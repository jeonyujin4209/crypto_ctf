# Extended GCD
- **출처**: CryptoHack - Introduction
- **난이도**: 20 pts
- **카테고리**: Mathematics
- **technique**: extended_euclidean_algorithm

## 문제 요약
p=26513, q=32321에 대해 p*u + q*v = gcd(p,q) 를 만족하는 u, v 구하기.

## 풀이
확장 유클리드 알고리즘. 두 수가 소수이므로 gcd=1.
u=10245, v=-8404 → 작은 값 = -8404

**인사이트**: RSA에서 모듈러 역원 계산에 필수.

## 답
`-8404`
