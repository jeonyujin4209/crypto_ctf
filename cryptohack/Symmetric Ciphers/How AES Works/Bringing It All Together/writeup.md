# Bringing It All Together
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 50 pts
- **카테고리**: AES
- **technique**: aes_full_decryption

## 문제 요약
AES-128 전체 복호화 구현. KeyExpansion + 10라운드 역순 적용.

## 풀이
복호화 순서:
1. AddRoundKey (round_key[10])
2. 라운드 9~1 반복: inv_shift_rows → inv_sub_bytes → AddRoundKey → inv_mix_columns
3. 마지막: inv_shift_rows → inv_sub_bytes → AddRoundKey (round_key[0])

## 플래그
`crypto{MYAES128}`
