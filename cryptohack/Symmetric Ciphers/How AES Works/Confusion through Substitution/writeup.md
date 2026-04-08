# Confusion through Substitution
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 25 pts
- **카테고리**: AES
- **technique**: sub_bytes, s_box, inv_s_box

## 문제 요약
SubBytes: state 행렬의 각 바이트를 S-box 룩업 테이블로 치환. 역방향(inv_s_box) 적용.

## 풀이
`inv_s_box[byte]` 로 각 바이트 역치환.

**인사이트**: S-box는 GF(2^8)에서의 모듈러 역원 + 아핀 변환. 비선형성(confusion) 제공.

## 플래그
`crypto{l1n34rly}`
