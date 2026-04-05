# Dancing Queen
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 120 pts
- **카테고리**: ChaCha20
- **technique**: chacha20_missing_addition_invertible

## 문제 요약
커스텀 ChaCha20 구현에서 최종 상태 덧셈(final state addition)이 누락되어 있다. 이로 인해 순열(permutation)이 가역적(invertible)이 되어, 알려진 평문으로부터 키를 복원할 수 있다.

## 풀이
1. `msg`와 `msg_enc`를 XOR하여 keystream을 추출한다.
2. keystream을 32비트 워드 단위의 상태(state)로 변환한다.
3. `inner_block`의 10라운드를 역으로 수행(invert)하여 초기 상태를 복원한다. 초기 상태에 키가 포함되어 있다.
4. 복원된 키로 `flag_enc`를 복호화한다.

## 플래그
`crypto{M1x1n6_r0und5_4r3_1nv3r71bl3!}`
