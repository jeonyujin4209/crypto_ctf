# Chinese Remainder Theorem

- **Category**: Modular Math
- **Points**: 40

## Challenge

다음 연립 합동식의 해를 구하라:

```
x ≡ 2 (mod 5)
x ≡ 3 (mod 11)
x ≡ 5 (mod 17)
```

x ≡ a (mod 935)에서 a를 제출. (935 = 5 × 11 × 17)

## Background: Chinese Remainder Theorem (CRT)

모듈러가 쌍별 서로소(pairwise coprime)이면, 연립 합동식의 해가 N = n1 × n2 × ... × nk를 법으로 유일하게 존재.

각 n_i에 대해:
- N_i = N / n_i
- x = Σ (a_i × N_i × N_i^(-1) mod n_i) mod N

## Solution

손계산도 가능:
1. x = 5 + 17k (가장 큰 모듈러부터)
2. 5 + 17k ≡ 3 (mod 11) → k ≡ 7 (mod 11) → k = 7 + 11j
3. x = 124 + 187j, 124 + 187j ≡ 2 (mod 5) → j ≡ 4 (mod 5) → j = 4
4. x = 124 + 748 = 872

## Answer

`872`
