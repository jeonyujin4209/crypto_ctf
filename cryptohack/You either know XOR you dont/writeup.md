# You either know, XOR you don't
- **출처**: CryptoHack - Introduction
- **난이도**: 30 pts
- **카테고리**: XOR
- **technique**: known_plaintext_attack, repeating_key_xor

## 문제 요약
반복 키 XOR 암호화. 플래그 포맷 "crypto{"를 알고 있으므로 키 복원 가능.

## 풀이
1. known plaintext "crypto{" XOR ciphertext → 키 일부 "myXORke" 추출
2. 패턴으로 전체 키 "myXORkey" 추정
3. 전체 복호화

**인사이트**: 플래그 포맷(known plaintext)이 있으면 repeating-key XOR은 즉시 깨짐.

## 플래그
`crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`
