# Structure of AES
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 15 pts
- **카테고리**: AES
- **technique**: matrix_byte_conversion

## 문제 요약
4x4 바이트 행렬을 바이트 배열로 변환. `matrix2bytes()` 구현.

## 풀이
`bytes(sum(matrix, []))` — 2D 리스트를 flatten 후 bytes 변환.

## 플래그
`crypto{inmatrix}`
