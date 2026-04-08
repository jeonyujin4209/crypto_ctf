# Flipping Cookie
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 60 pts
- **카테고리**: AES, CBC
- **technique**: cbc_bit_flipping

## 문제 요약
CBC 암호화된 쿠키에서 "admin=False"를 "admin=True"로 변경.

## 풀이
CBC에서 P1 = D(C1) ^ IV. IV를 조작하면 P1을 원하는 값으로 변경 가능.
`new_iv[i] = iv[i] ^ original[i] ^ target[i]`

**인사이트**: CBC는 무결성(integrity)을 보장하지 않음. 인증(MAC)이 필수.

## 플래그
`crypto{4u7h3n71c4710n_15_3553n714l}`
