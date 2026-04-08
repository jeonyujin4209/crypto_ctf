# Pad Thai
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 80 pts
- **카테고리**: AES, CBC, Padding Oracle
- **technique**: classic_padding_oracle_attack

## 문제 요약
AES-CBC 암호화된 메시지. encrypt/unpad(패딩 검증)/check 오라클 제공. 노이즈 없음.

## 풀이
클래식 패딩 오라클 공격:
1. `encrypt` → IV + C1 + C2 (메시지 32바이트 = 2블록)
2. 바이트 15부터 0까지 역순으로:
   - 이전 블록(IV/C1) 바이트를 조작하여 패딩 검증
   - pad_val=1: 마지막 바이트가 0x01이 되는 값 탐색
   - pad_val=2: 마지막 2바이트가 0x02가 되는 값 탐색
   - ...반복
3. intermediate = guess ^ pad_val, plaintext = intermediate ^ prev_block
4. 평문이 hex 문자(0-9,a-f)임을 이용해 검증

## 플래그
`crypto{if_you_ask_enough_times_you_usually_get_what_you_want}`
