# Bean Counter
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 60 pts
- **카테고리**: AES/CTR
- **technique**: ctr_counter_bug_known_plaintext

## 문제 요약
커스텀 CTR 카운터 구현에 버그가 있다. `step_up=False`로 설정되어 있고, decrement 로직에서 `self.stup=0`을 사용하므로 카운터가 절대 변하지 않는다. 결과적으로 모든 블록에 동일한 keystream이 적용된다.

## 풀이
1. 암호화된 데이터는 PNG 파일이다. PNG 헤더의 처음 16바이트는 알려진 값이다 (`\x89PNG\r\n\x1a\n` + IHDR 청크 시작).
2. 알려진 평문 16바이트와 암호문 첫 16바이트를 XOR하여 keystream을 추출한다.
3. 카운터 버그로 인해 모든 블록이 동일한 keystream을 사용하므로, 추출한 keystream으로 전체 암호문을 XOR하여 복호화한다.

## 플래그
`crypto{hex_bytes_beans}`
