# Network Attacks
- **출처**: CryptoHack - Introduction
- **난이도**: 5 pts
- **카테고리**: General
- **technique**: pwntools_json_socket

## 문제 요약
서버에 JSON `{"buy": "flag"}` 를 보내면 플래그 반환.

## 풀이
pwntools `remote()` 로 접속 후 JSON send/recv.

## 플래그
`crypto{sh0pp1ng_f0r_fl4g5}`
