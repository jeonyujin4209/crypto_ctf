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
2. **`skills/README.md` 인덱스를 먼저 훑기** — 문제 구조 키워드(DLP 타입, group, ring 구조)로 매칭
3. 관련 skill 여러 개 읽기 (`attack/` 만 아니라 `failures/` `tools/` 도)
4. 로컬 검증 → 서버 실행
5. 풀이 후 skill 추출 논의

## 접근 원칙 (중요)
- **복잡도 계산 전에 벤치 먼저**. DLP/factoring 어려워 보이면 Pollard rho 수식 대신 **작은 사이즈 실측**부터
  (예: 128-bit F_p* DLP는 Sage로 ~50초, Pollard rho 추정치 30년과 완전 다름)
- **Docker sage 30초+ 멈춤 = 환경 문제 의심**. 알고리즘 느림 아님 (→ `tools/sage-dlp-fp-feasibility` Windows 섹션)
- **"k bound < order" 조건 체크**. 256-bit key + ~384-bit order면 모든 factor 풀 필요 X. Partial PH로 충분

## 연구 원칙
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
