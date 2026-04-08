# Logon Zero
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 80 pts
- **카테고리**: AES/CFB-8
- **technique**: cfb8_zerologon_cve_2020_1472

## 문제 요약
CFB-8 모드에서 IV를 전부 0(`0x00 * 16`)으로 설정할 경우, `E(0x00*16)`의 첫 바이트가 0이면 모든 복호화된 바이트가 0이 된다. 이 확률은 키당 1/256이다.

## 풀이
1. `token = 0x00 * 28`을 서버에 전송한다.
2. CFB-8에서 all-zero IV 조건이 맞으면 `password_length`가 0으로 복호화되어 비밀번호가 빈 문자열(`""`)이 된다.
3. 빈 비밀번호로 인증을 시도한다.
4. 키에 따라 확률적으로 성공하므로, 성공할 때까지 연결을 재시도한다 (약 256번 시도).

## 플래그
`crypto{Zerologon_Windows_CVE-2020-1472}`
