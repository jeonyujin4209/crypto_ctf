# Modes of Operation Starter
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 15 pts
- **카테고리**: AES, ECB
- **technique**: ecb_decrypt_oracle

## 문제 요약
서버가 같은 키로 encrypt_flag()와 decrypt() API를 제공. ECB 모드라 그냥 암호문을 decrypt에 넣으면 됨.

## 풀이
1. `/encrypt_flag/` → 암호문 획득
2. `/decrypt/<ciphertext>/` → 평문 복호화

**인사이트**: 서버가 복호화 오라클을 제공하면 ECB는 즉시 깨짐.

## 플래그
`crypto{bl0ck_c1ph3r5_4r3_f457_!}`
