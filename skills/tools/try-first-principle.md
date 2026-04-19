---
name: try-first-principle
description: AI 반복 실수 1위 — 이론만으로 infeasible 판정하고 안 해봄. 생각을 실험으로 전환하는 범용 원칙
type: skill
---

# Try-First Principle (범용 ⭐)

## 핵심
**"~ 일 것 같다"는 전부 실험 대상**. 모든 판단의 근거는 실측이어야 함.

## 증상 체크
다음 중 하나라도 해당하면 당장 실행 모드로 전환:
- "이 알고리즘은 2⁶³이라 infeasible" → 복잡도 계산만 하고 실행 X
- "이 lattice reduction은 안 될 것" → LLL 실제 안 돌려봄
- "서버가 이런 반응할 것" → 서버 접속 안 함
- "전체 로직 파악 후 구현" → 코드 0줄
- "증명 안 되니 이 접근 안 먹힐 듯" → 실측이 곧 증거인데

## 변환 패턴

| 분석형 사고 | 실험형 행동 |
|---|---|
| "이 DLP는 Pollard rho라 feasibility..." | 작은 prime부터 벤치 → scaling 보기 |
| "LLL이 이 격자 차원에서 reduce 못할 것" | 일단 LLL 호출, 결과 norm 보기 |
| "서버는 이런 포맷일 것" | `nc host port` 또는 connect 먼저 |
| "이 attack이 먹힐지 증명" | 로컬 재현 후 attack 함수 짜기 |
| "도구 A vs B 뭐가 빠를지" | 양쪽 다 짧게 돌려보기 |
| "이 hash는 collision 찾기 힘들 것" | 생일역설 계산 대신 small brute 돌려보기 |

## 근본 원인
AI는 "맞는 답"에 보상 → 시도 실패 회피 → 분석으로 대신.
하지만 CTF는 **실패 많이 해본 쪽이 이김**.
머릿속 추론은 편향되지만 실측은 객관적.

## 규칙
1. **판단 근거 명시**: "실측 X초 걸림" vs "이론상 X년" — 후자만 있으면 실측으로 보강
2. **도구 선택 기준**: 이론 성능 ≠ 실제 성능 (Sage znlog이 Pollard rho 예상치보다 1000배 빠른 경우 등)
3. **부분 풀이라도 시작**: 전체 flow 모르겠으면 아는 부분부터
4. **관찰 > 가정**: 서버/시스템 동작은 문서보다 실제 trace가 정확

## 실제 케이스
**Unevaluated TETCTF 2021**:
- 함정: 127-bit F_p\* DLP → Pollard rho 2⁶³·⁵ → "30년 걸림, 불가능" → CADO-NFS 검토
- 실제: `sage: discrete_log(h, g, ord=q)` = **49.6초** (PARI 2.17이 index calculus 자동 선택)
- 원인: 수학적 복잡도로만 판단, tool 한 번도 안 돌려봄
- 교훈: Sage/PARI/기타 성숙한 도구는 **수식보다 10²~10⁶배 빠른 알고리즘 내장**되어 있을 수 있음

## 관련
- `tools/stuck-checklist-5-questions` — 이 원칙이 Q0
- `failures/premature-dlp-infeasibility` — DLP 특화 구체 사례
