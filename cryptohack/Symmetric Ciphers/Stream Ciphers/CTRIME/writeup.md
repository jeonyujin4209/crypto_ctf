# CTRIME
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 70 pts
- **카테고리**: AES/CTR
- **technique**: compression_oracle_crime_attack

## 문제 요약
서버가 `(user_input + FLAG)`를 압축한 뒤 CTR 모드로 암호화한다. CRIME 공격을 적용할 수 있다.

## 풀이
1. Byte-at-a-time 방식으로 플래그를 한 바이트씩 복구한다.
2. 후보 바이트를 입력에 추가했을 때, 해당 바이트가 실제 플래그와 일치하면 압축률이 높아져 암호문 길이가 줄어든다.
3. 가장 짧은 암호문을 생성하는 후보 바이트를 선택하여 플래그를 순차적으로 복원한다.

## 플래그
`crypto{CRIME_571ll_p4y5}`
