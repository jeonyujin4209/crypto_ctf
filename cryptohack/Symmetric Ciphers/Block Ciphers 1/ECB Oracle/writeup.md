# ECB Oracle
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 60 pts
- **카테고리**: AES, ECB
- **technique**: ecb_byte_at_a_time

## 문제 요약
ECB 모드에서 `encrypt(user_input || FLAG)`. 복호화 함수 없음.

## 풀이 (Byte-at-a-time Attack)
1. 패딩 길이 조절 → 미지 바이트를 블록 경계 끝에 배치
2. 레퍼런스 암호문 블록 저장
3. 알려진 바이트 + 후보 1바이트 → 암호문 비교
4. 일치하는 후보 = 다음 플래그 바이트
5. 반복 (플래그 길이만큼)

**인사이트**: ECB는 동일 평문 → 동일 암호문이므로 바이트 단위 오라클 공격 가능.

## 플래그
`crypto{p3n6u1n5_h473_3cb}`
