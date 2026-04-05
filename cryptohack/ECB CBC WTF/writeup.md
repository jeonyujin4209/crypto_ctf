# ECB CBC WTF
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 55 pts
- **카테고리**: AES, CBC, ECB
- **technique**: cbc_ecb_mode_mismatch, manual_cbc_decrypt

## 문제 요약
CBC로 암호화, ECB로만 복호화 가능. ECB decrypt를 이용해 CBC를 수동 복호화.

## 풀이
CBC 복호화 공식: P_i = D(C_i) ^ C_{i-1}
1. encrypt_flag → IV || C1 || C2 || ...
2. 각 C_i를 ECB decrypt → D(C_i)
3. D(C_i) ^ C_{i-1} = P_i

## 플래그
`crypto{3cb_5uck5_4v01d_17_!!!!!}`
