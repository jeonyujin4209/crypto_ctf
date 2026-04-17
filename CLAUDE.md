# Crypto CTF Solver — 작업 규칙

## 풀이 워크플로우
1. challenge 파일 분석 → 취약점 파악
2. 어려우면 `skills/` 폴더 참고
3. Python 우선 (Sage 지양)
4. 로컬 검증 후 서버 실행
5. 풀이 후 skill 추출 여부 논의

## 코드 작성
- solve.py에 상단 docstring으로 취약점/공격 요약
- 임시 테스트 파일(test_*.py, *.log)은 커밋 전 삭제
- pwntools 사용 시 HOST는 `archive.cryptohack.org`

## 출력 규칙
- 분석 과정은 간결하게 (핵심만 요약, 중간 디버그 출력 최소화)
- 분석 퀄리티는 절대 줄이지 않음
- 서버 실행 시 전체 로그 대신 핵심 결과만 보고

## 흔한 실수 방지
- Z3 default Solver() 느리면 `Then('simplify', 'bit-blast', 'sat')` tactic 시도
- MT19937 twist는 in-place: phase 2(i≥227)와 last element(i=623)는 이미 업데이트된 new 값 참조
- CryptoHack pkcs1 라이브러리는 SHA-1이 기본 (SHA-256 아님)
- sympy discrete_log는 p^k에서 OOM → p-adic lifting 사용
- N=p^k 형태가 필요하면 smooth prime 검색 대신 직접 prime power 사용

## Git
- 커밋 메시지: "Solve [문제명] + [skill 추가 시 언급]"
- skill 파일 추가 시 skills/README.md도 업데이트
