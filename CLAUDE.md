# Crypto CTF Solver

## 목적
AI가 skill DB만으로 CTF 풀 수 있는가 연구. 문제 복붙 풀이 금지.
향후 CryptoHack 외 다른 플랫폼 (TETCTF, HKCERT 등) 도 테스트 대상.

## 환경
- Docker 데스크탑 있음 (`sagemath/sagemath` 이미지 pull됨)
- 무거운 DLP/lattice는 Sage docker, 나머지는 Python
- 서버 주소/포트는 각 challenge의 README.md 또는 source에서 확인

## 워크플로우
1. Challenge 파일 분석 → 취약점 파악
2. `skills/` 먼저 참고 (`attack/` `failures/` `tools/`)
3. 로컬 검증 → 서버 실행
4. 풀이 후 skill 추출 논의

## 원칙
- **문제명 직접 검색 금지** (유사 기술로 푸는 다른 CTF 검색은 OK)
- 못 풀면 **"왜 못 푸는지" 명시** (모델 knowledge vs 현재 상황 비교)
- 분석 퀄리티 절대 줄이지 않음 (출력은 간결하게)

## 코드 규칙
- `solve.py` 상단 docstring에 취약점/공격 요약
- 임시 파일 (`test_*.py`, `*.log`) 커밋 전 삭제
- 디버그 출력 최소화, 서버 로그도 핵심 결과만

## Git
- 커밋: `"Solve [문제명] + [skill 언급]"`
- skills/ 추가 시 `skills/README.md` 인덱스 업데이트
