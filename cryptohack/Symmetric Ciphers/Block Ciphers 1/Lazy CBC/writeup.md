# Lazy CBC
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 60 pts
- **카테고리**: AES, CBC
- **technique**: iv_equals_key_attack

## 문제 요약
IV = KEY로 CBC 사용. 에러 메시지에서 복호화된 평문 hex 유출.

## 풀이
1. 임의 평문 암호화 → C1 획득
2. C1 || 00..00 || C1 을 decrypt에 전송
3. UTF-8 에러 → 복호화된 P1, P2, P3 유출
4. KEY = P1 ^ P3 (P1 = D(C1)^KEY, P3 = D(C1))

**인사이트**: IV는 반드시 랜덤이어야 하며, 절대 키와 같으면 안 됨.

## 플래그
`crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}`
