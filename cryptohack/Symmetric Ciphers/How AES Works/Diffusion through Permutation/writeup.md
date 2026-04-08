# Diffusion through Permutation
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 30 pts
- **카테고리**: AES
- **technique**: inv_shift_rows, inv_mix_columns

## 문제 요약
ShiftRows + MixColumns의 역연산 적용.

## 풀이
1. `inv_mix_columns()` — GF(2^8) 행렬곱 역연산
2. `inv_shift_rows()` — 행 시프트 역방향 (shift_rows의 반대 방향)

**인사이트**: ShiftRows + MixColumns = diffusion. 1비트 변경 → 2라운드 후 모든 바이트에 영향 (Avalanche effect).

## 플래그
`crypto{d1ffUs3R}`
