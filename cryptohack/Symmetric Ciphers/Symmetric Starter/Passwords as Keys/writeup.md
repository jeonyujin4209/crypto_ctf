# Passwords as Keys
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 50 pts
- **카테고리**: AES, ECB
- **technique**: dictionary_attack, weak_key_derivation

## 문제 요약
AES 키가 `md5(영어단어)`로 생성됨. 사전 파일(~10만 단어)로 브루트포스 가능.

## 풀이
1. `/encrypt_flag/` → 암호문 획득
2. 사전 파일 다운로드 (`/usr/share/dict/words`)
3. 각 단어에 대해 `md5(word)` → AES-ECB 복호화 시도
4. `crypto{`로 시작하는 평문 발견 시 종료

**인사이트**: 패스워드 기반 키 생성은 키 공간을 사전 크기로 축소시킴. CSPRNG으로 키를 생성해야 함.

## 플래그
`crypto{k3y5__r__n07__p455w0rdz?}`
