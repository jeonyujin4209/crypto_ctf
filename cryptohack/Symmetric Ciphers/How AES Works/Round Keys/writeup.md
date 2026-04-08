# Round Keys
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 20 pts
- **카테고리**: AES
- **technique**: add_round_key, xor_matrix

## 문제 요약
AddRoundKey: state 행렬과 round_key 행렬을 XOR.

## 풀이
각 위치에서 `state[i][j] ^ round_key[i][j]`.

## 플래그
`crypto{r0undk3y}`
