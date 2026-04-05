# Transparency
- **출처**: CryptoHack - Introduction
- **난이도**: 50 pts
- **카테고리**: Data Formats
- **technique**: certificate_transparency_log, crt_sh_lookup

## 문제 요약
PEM 공개키가 주어지고, 이 키를 사용하는 cryptohack.org 서브도메인을 찾아 방문.

## 풀이
1. PEM에서 n, e 추출
2. crt.sh (CT 로그 검색) 에서 `cryptohack.org` 검색
3. 서브도메인 목록에서 `thetransparencyflagishere.cryptohack.org` 발견
4. 방문하면 플래그 반환

**인사이트**: Certificate Transparency는 모든 CA 발급 인증서를 공개 로그에 기록. crt.sh로 검색 가능.

## 플래그
`crypto{thx_redpwn_for_inspiration}`
