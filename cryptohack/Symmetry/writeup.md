# Symmetry
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 50 pts
- **카테고리**: AES/OFB
- **technique**: ofb_symmetry

## 문제 요약
OFB 모드는 대칭(symmetry) 성질을 갖는다. 즉, 동일한 IV로 암호문을 다시 암호화하면 복호화가 된다.

## 풀이
1. `encrypt_flag`를 호출하면 `IV + ct`가 반환된다.
2. OFB 모드에서는 keystream이 IV와 키에만 의존하므로, encrypt와 decrypt가 동일한 연산(XOR)이다.
3. 반환된 IV와 ct를 그대로 `encrypt(ct, IV)`로 보내면 평문(플래그)이 복원된다.

## 플래그
`crypto{0fb_15_5ymm37r1c4l_!!!11!}`
