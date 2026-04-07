# Noisy Oracle: 통계적 접근으로 노이즈 극복

## 유형
Noisy Padding Oracle (확률적 응답을 주는 오라클)

## 문제 상황
패딩 오라클이 정확한 True/False를 주지 않고, 확률적으로 뒤집힌 응답을 준다. 단일 쿼리로는 정답을 알 수 없다.

## 왜 못 풀었나 (A)

### 시도 1-2: Bayesian argmax / Thompson Sampling
틀린 후보에 고착되면 탈출에 수백 쿼리 낭비. 16개 후보에 round-robin하면 evidence가 분산되어 구분 불가.

### 시도 3-4: Sequential Halving (단계별 제거)
제거는 돌이킬 수 없음. 운 나쁘게 정답이 초반 라운드에서 제거되면 복구 불가. 생존한 wrong arm은 "운 좋은 놈들"이라 이후에도 유리 (selection bias).

### 시도 5-7: 고정 Phase + Duel
이론적 분석이 너무 낙관적. 실제 바이트당 정확도가 이론치의 75%에 불과.

### 공통 실패 원인
1. **바이트당 정확도 과대평가** (이론 99% vs 실제 75-85%)
2. **Selection bias 무시** — 생존한 틀린 후보는 평균보다 강함
3. **한 번에 성공하려고 함** — 32바이트 연속 정답 확률이 극히 낮음

## 어떻게 해결했나 (B)

### Adaptive Top-2 with LLR
```
1. 스크리닝: 16개 후보 x 4쿼리 = 64쿼리 → 초기 LLR 추정
2. 적응적 집중: 매 라운드 LLR 상위 2개만 쿼리
   - 틀린 후보: 쿼리할수록 LLR 자연 하락 (-0.081/query)
   - 맞는 후보: top-2 진입 후 최종 duel 승리
3. 최종 선택: LLR 최대값
```

**핵심 차이: "제거" vs "자연 하락"**
- Sequential Halving: 영구 제거 → 실수 복구 불가
- Adaptive Top-2: 틀린 후보가 자연적으로 LLR 하락 → 자기 교정

### 재시도 전략
- 바이트당 86% 정확도 → 0.86^32 ≈ 0.7% per attempt
- **한 번에 성공은 불가능** — 이것이 핵심 깨달음
- 수백 번 재시도: 500회 시도 시 P(success) ≈ 97%

## 적용 범위
- 노이즈가 있는 패딩 오라클 (확률적 응답)
- 쿼리 제한이 있는 오라클 (budget 관리 필요)
- 임의의 noisy binary channel에서 후보 식별 문제

## 수치
| 전략 | 바이트당 정확도 |
|------|---------------|
| Uniform (제거 없음) | 59% |
| Sequential Halving | 75% |
| **Adaptive Top-2** | **86%** |

## 출처
- CryptoHack: Oracular Spectacular (150pts, Symmetric Ciphers)
