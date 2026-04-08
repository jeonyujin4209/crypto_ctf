# Successive Powers

- **Category**: Brainteasers Part 1
- **Points**: 60

## Challenge

{588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237}은 정수 x의 연속된 거듭제곱을 세 자리 소수 p로 나눈 나머지이다. p와 x를 구하라.

## Solution

연속 세 값 a, b, c에 대해 b = a*x mod p, c = b*x mod p이므로:
- b^2 ≡ a*c (mod p) → p | (b^2 - a*c)

모든 연속 트리플에서 (b^2 - a*c)의 GCD를 구하면 p를 얻는다.

```
GCD = 919 (이미 세 자리 소수)
p = 919
x = vals[1] * vals[0]^(-1) mod p = 665 * 588^(-1) mod 919 = 209
```

검증: 모든 연속 쌍에서 vals[i] * 209 mod 919 = vals[i+1] 확인.

## Answer

`crypto{919,209}`
