# Quadratic Residues

- **Category**: Modular Math
- **Points**: 25

## Challenge

p = 29, ints = [14, 6, 11] 중에서 이차잉여(Quadratic Residue)를 찾고, 두 제곱근 중 작은 값을 제출.

이차잉여란: a^2 ≡ x (mod p)를 만족하는 a가 존재하면 x는 이차잉여.

## Solution

p=29로 작으므로 a=1부터 p-1까지 전수탐색.

- 14: 제곱근 없음 (Non-Residue)
- **6: a=8, 8^2 = 64 ≡ 6 (mod 29)** (Residue)
- 11: 제곱근 없음 (Non-Residue)

두 근은 8과 21 (= 29-8). 작은 값 제출.

## Answer

`8`
