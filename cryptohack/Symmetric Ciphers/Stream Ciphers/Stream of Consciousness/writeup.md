# Stream of Consciousness
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 80 pts
- **카테고리**: AES/CTR
- **technique**: ctr_nonce_reuse_many_time_pad

## 문제 요약
CTR 모드에서 `Counter.new(128)`을 사용하여 카운터가 항상 0부터 시작하고 동일한 KEY를 사용하므로, 매번 같은 keystream이 생성된다. Many-time pad 문제이다.

## 풀이
1. 동일한 keystream으로 암호화된 다수의 암호문을 수집한다.
2. 출력 가능한 ASCII 문자의 통계적 특성을 이용하여 keystream을 복구한다.
3. 복구된 keystream으로 각 암호문을 XOR하여 평문을 얻는다.

## 플래그
`crypto{k3y57r34m_r3u53_15_f474l}`
