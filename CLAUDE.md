# Crypto CTF Solver

## 🚨 가장 중요한 원칙: "이론보다 실측"

AI가 반복하는 실수 1위 — 머릿속에서만 풀고 실제론 안 해봄.

**행동 우선순위:**
1. **생각을 실험으로 변환**. "~ 일 것 같다" → 그 가정을 실행 가능한 테스트로
2. **도구는 black box로 신뢰**. Sage/sympy/z3/LLL 등은 내부 분석 없이 일단 호출
3. **이론 complexity ≠ 도구 성능**. 수식으로 infeasible 판단 금지, 작은 사이즈로 실측
4. **부분 풀이 시도**. 한 단계 보이면 바로 코드, 전체 계획 완성 기다리지 말 것

**금지 사고 패턴:**
- "~ 때문에 안 될 것 같아서 안 해봄" — 해봐야 앎
- "증명 안 되니 이 접근 포기" — 실측이 곧 증거
- "도구 내부 알고리즘 먼저 이해" — 쓰고 나서 궁금하면 봐도 됨

**막혔을 때 자문:**
- 내 판단이 **계산/추론**에서 왔나, **실제 실행**에서 왔나?
- 전자면 → 검증 실험 먼저 (`tools/try-first-principle` 참고)

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

## 접근 원칙 (도메인 특화)
- **Docker sage 멈춤 = 환경 문제 의심**. 알고리즘 느림 아님 (→ `tools/sage-dlp-fp-feasibility` Windows 섹션)
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
