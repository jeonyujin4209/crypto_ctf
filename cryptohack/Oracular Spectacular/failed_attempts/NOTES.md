# Oracular Spectacular - 풀이 기록

## 챌린지 분석
- AES-CBC, 메시지 = `urandom(16).hex()` → 32자 hex (2 AES 블록)
- 노이즈 패딩 오라클: `good ^ (rng.random() > 0.4)`
  - valid padding → True 40%, False 60%
  - invalid padding → True 60%, False 40%
- 쿼리 제한: 12,000회
- hex 제약: 바이트당 후보 16개 (256 → 16)
- 정보 이론: 쿼리당 KL = 0.081 nats, 16 후보를 0.999 확신으로 구분하려면 ~9.62 nats 필요

## 핵심 수학

| 항목 | 수식/값 |
|------|---------|
| 쿼리당 정보 | KL(0.4‖0.6) = 0.081 nats |
| 쌍별 evidence | `2 × (queries on v + queries on j) × 0.081` |
| 0.999 도달 | 9.62 nats 필요 → 최소 ~120 relevant queries |
| Round-robin 16 효율 | 0.010 nats/query (극히 비효율) |
| Round-robin 2 효율 | 0.081 nats/query (최대 효율) |

---

## 시도 1: 베이지안 argmax

**전략**: 사후확률 1위 후보만 반복 쿼리, log-odds threshold > 0.9999

**결과**: ❌ incorrect message (10,199 쿼리)

**실패 원인**: invalid 후보에 고착 → 탈출에 수십~수백 쿼리 낭비. 한 바이트 오류 → cascading failure.

---

## 시도 2: Thompson Sampling + round-robin

**개선**: argmax 대신 사후확률 비례 샘플링으로 exploration/exploitation 균형

**결과**: ❌ incorrect message (11,200 쿼리)

**실패 원인**: 제거 threshold(0.001)이 너무 보수적 → 16개 전부에 round-robin → 바이트당 3.5 nats밖에 축적 못함 → posterior 0.27~0.90

---

## 시도 3: 단계별 제거 (10 rounds/phase, halve) + 전체 후보 업데이트

**개선**: 10 rounds마다 절반씩 제거 (16→8→4→2), 후보 개수 줄여서 evidence 집중

**결과**: ❌ incorrect message (11,200 쿼리)

**실패 원인**: **제거된 후보의 log_p 드리프트**
- 제거된 후보도 매 쿼리마다 LI_T/LI_F 배경 업데이트를 받음
- 랜덤 변동으로 제거된 후보의 log_p > 유효 후보 가능
- 최종 답 선택이 전체 16 후보 대상 → 제거된 후보가 선택됨

---

## 시도 4: 단계별 제거 + active만 업데이트 + active에서만 선택

**개선**: 
- 제거된 후보 업데이트 차단 (`for j in active`)
- 최종 답을 active 후보 중에서만 선택

**결과**: ❌ incorrect message (11,800 쿼리). posterior 0.69~0.99.

**실패 원인**: 드리프트는 해결됐지만 새로운 문제 발견
- posterior 0.50인 바이트 3개 → 유효 후보가 제거되어 2개 invalid끼리 duel (수렴 불가)
- **비독립성(correlation)**: 모든 쌍의 evidence가 valid 후보 쿼리를 공유 → 상관계수 0.50
- valid의 운이 나쁘면 여러 invalid에 동시에 패배 → 이론치(0.2%)보다 제거율 높음 (~1-3%)

---

## 시도 5: Always-query-top-1 (제거 없는 적응형)

**개선**: 후보 제거를 완전히 제거. 항상 posterior 1위 후보만 쿼리.
- Invalid 1위 → 자연 하락 (-0.081 nats/query)
- Valid 1위 → 자연 상승 (+0.081 nats/query)

**결과**: ❌ incorrect message (11,800 쿼리). posterior 0.06~0.17.

**실패 원인**: **argmax trap 재발**
- Invalid 후보가 운 좋게 1위 유지 → 전체 budget 소모
- 16개 후보 순차 탐색: 평균 ~8개 invalid 거쳐야 valid 도달 → budget 부족
- Python `max()` tie-breaking으로 항상 index 순 → valid이 뒤쪽이면 도달 불가

---

## 시도 6: 고정 phase + 짧은 duel (M1=9, M2=12, M3=26, M4=13)

**개선**: 수학적 최적화로 phase별 rounds 결정. Active만 업데이트.

**결과**: ❌ incorrect message. posterior 0.50~0.99, 0.50인 바이트 3개.

**실패 원인**: **duel이 너무 짧음** (M4=13 rounds = 26 queries = 2.1 nats from duel)
- 이전 phase에서 ~7.6 nats 축적했지만, variance(SD=4.34)로 인해 P(evidence<0) = 1.3%/byte
- duel error가 지배적 오류원: 32 bytes × 1.3% = ~34% 실패 확률
- Phase별 제거는 안전 (0.3%/byte)하지만 duel에서 날림

---

## 시도 7: 고정 phase + 긴 duel (M1=5, M2=6, M3=30, M4=62) ← 현재 실행 중

**개선**: 
- Phase 1-3 rounds를 최소화 (안전 범위 내에서)
- 절약한 budget을 전부 duel에 투입 → 62 rounds (124 queries)
- Duel evidence: 2×62×0.081 = 10.0 nats (이전 2.1 대비 5배)

**Budget 배분**:
| Phase | Rounds | Active | Queries | 누적 |
|-------|--------|--------|---------|------|
| P1 | 5 | 16 | 80 | 80 |
| P2 | 6 | 8 | 48 | 128 |
| P3 | 30 | 4 | 120 | 248 |
| P4 | 62 | 2 | 124 | 372 |

**이론적 오류율**:
- P1 제거: 0.1%/byte
- P2 제거: 0.1%/byte
- P3 제거: 0.3%/byte (p=0.032, P(≤1 of 3)=0.997)
- Duel 오류: 0.2%/byte (P(evidence<0) = Φ(-3.05) = 0.001)
- 합계: ~0.7%/byte → 32 bytes: **~80% 성공률**

**결과**: ❌ incorrect message (5회 병렬 실행 전부 실패). posterior 0.69~1.00.

**실패 원인**: 이론 vs 실제 괴리
- 이론적 per-byte error 0.7% → 실제 ~5%+ (10연속 실패로 추정)
- **ranking은 독립 score 기반** (`score[i] = 0.405 × (False_i - True_i)`)이지만
- **selection bias**: 이전 phase 생존 invalid는 Phase 1에서 "운 좋았던" 놈들 → Phase 2+에서도 유리
- **per-byte ~95% 정확도여도** 0.95^32 = 19% 성공률
- p=0.69 (evidence ≈ 0.81 nats)는 "duel에서 2:1 비율" = evidence 부족 신호

---

## 시도 8: 독립 LLR + 소프트 제거 (ChatGPT 버전)

**파일**: `solve_llr_independent.py`

**개선**:
- **후보별 독립 추적**: `(n_i, t_i, LLR_i)` — 후보 간 coupling 완전 제거
- **소프트 제거**: 16→10→6→3 (기존 16→8→4→2보다 보수적)
- **조기 세션 폐기**: `p < 0.68 or gap < 0.75`이면 즉시 abort → cascading 방지
- `LLR_i = t_i × log(0.4/0.6) + (n_i - t_i) × log(0.6/0.4)` — True 많으면 invalid, False 많으면 valid

**결과**: ❌ 5회 병렬 전부 실패 (4개: incorrect message, 1개: 조기 abort 후 재시도 중 타임아웃)

**실패 원인**: 독립 LLR이라도 수학적 ranking은 동일
- `log_p[i] = constant + score[i]` → ranking은 어차피 같은 score 기반
- 조기 폐기(p<0.68)는 **명백한 실패만 감지**, 미묘한 실패(p=0.93이지만 틀린 경우)는 통과
- 0.93^32 ≈ 10% → 높은 posterior에도 전체 정확도는 낮음
- Stage 1 (4 queries×16 → top 10): per-byte ~10% 제거 위험 → 32바이트 중 하나 제거될 확률 ~96%

---

## 핵심 교훈 (시도 1~8 종합)

### 근본 한계
- **바이트당 375 쿼리**, 16 후보, 0.4/0.6 신호 → per-byte 정확도 ~93-97%가 한계
- **32바이트 연쇄**: 0.95^32 = 19%. 한 바이트만 틀려도 전체 실패
- **cascading error**: 바이트 k가 틀리면 k-1 ~ 0번 전부 오염 (패딩 조건 깨짐)

### 접근법별 결과

| 시도 | 핵심 전략 | per-byte p | 실패 원인 |
|------|-----------|-----------|-----------|
| 1 | argmax 고착 | 0.06~0.44 | invalid에 stuck |
| 2 | Thompson sampling | 0.27~0.90 | 제거 안 됨, evidence 부족 |
| 3 | 단계별 제거 (전체 update) | 0.14~0.90 | 제거된 후보 드리프트 |
| 4 | 단계별 제거 (active update) | 0.50~0.99 | valid 조기 제거, correlation |
| 5 | top-1만 쿼리 | 0.06~0.17 | argmax trap |
| 6 | 짧은 duel | 0.50~0.99 | duel evidence 부족 |
| 7 | 긴 duel (5회 병렬) | 0.69~1.00 | selection bias, 0.95^32=19% |
| 8 | 독립 LLR (5회 병렬) | 0.93~0.96 | 같은 ranking, 0.93^32=10% |

### 아직 시도하지 않은 전략
1. **2차 암호문 검증**: encrypt 2번 → 1차로 복구, 2차로 바이트별 검증 → 오류 바이트 찾아 교체
2. **Sequential Halving**: best-arm identification 최적 알고리즘
3. **다중 암호문 교차**: 3개 CT 독립 공격 → majority vote (budget 분산 문제 있음)
