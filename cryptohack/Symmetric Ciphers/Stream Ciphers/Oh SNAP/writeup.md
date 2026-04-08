# Oh SNAP
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 120 pts
- **카테고리**: RC4
- **technique**: rc4_fms_attack, related_key

## 문제 요약
RC4 키 = nonce + FLAG. nonce를 자유롭게 설정하고 키스트림 바이트를 관찰 가능.

## 풀이
Fluhrer-Mantin-Shamir (FMS) 공격:
1. nonce = [A, 0xFF, trial] (3바이트)으로 설정, trial = 0~255
2. 각 trial에 대해 partial KSA를 알려진 바이트로 실행
3. 첫 키스트림 바이트로 FLAG[target] 후보를 투표
4. 가장 많이 투표된 값 = FLAG 바이트
5. 바이트씩 확장

**인사이트**: RC4의 KSA가 키 바이트를 순차적으로 처리하므로, known-prefix 상태에서 다음 바이트를 통계적으로 추출 가능.

## 플래그
`crypto{w1R3d_equ1v4l3nt_pr1v4cy?!}`
