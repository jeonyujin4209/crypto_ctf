# Oracular Spectacular - 풀이 분석

## 문제 구조

- AES-CBC 암호화, 메시지 = `urandom(16).hex()` (32자 hex, 2블록)
- 노이즈 패딩 오라클: `good ^ (rng.random() > 0.4)`
  - valid padding → True 40%, False 60%
  - invalid padding → True 60%, False 40%
  - **신호 차이가 겨우 20%** (0.4 vs 0.6)
- 쿼리 제한: 12,000회
- hex 제약으로 바이트당 후보 16개 (256 → 16)

## 핵심 제약: 왜 어려운가

### 1. 정보 이론적 한계
- BSC(0.6) 채널 용량: 0.029 bits/query
- 32바이트 × 4bits = 128bits 필요
- 최소 쿼리: 128 / 0.029 ≈ 4,400회
- 예산 12,000회 → 이론적으로는 충분 (2.7배 여유)
- **하지만 패딩 오라클 구조가 정보 추출 효율을 제한함**

### 2. Cascading Error (연쇄 오류)
- 바이트 15 → 14 → 13 → ... → 0 순서로 공격
- 바이트 k가 틀리면 → 바이트 k-1 ~ 0 전부 오염
- inter[k]가 틀리면 이후 패딩 설정이 전부 깨짐
- **한 바이트 오류 = 해당 블록 전체 실패**

### 3. 바이트당 예산 부족
- 12,000 / 32 = 375 쿼리/바이트
- 16개 후보, 0.4 vs 0.6 신호 → 구분이 매우 어려움
- 바이트당 정확도 ~86%가 실질적 한계
- 0.86^32 ≈ 0.7% → 시도당 성공률이 매우 낮음

---

## 이전 시도들이 실패한 이유

### 시도 1-2: Bayesian argmax / Thompson Sampling
- **문제**: argmax trap — 틀린 후보에 고착되면 탈출에 수백 쿼리 낭비
- Thompson Sampling도 제거 threshold가 보수적 → 16개 전부에 round-robin → evidence 분산

### 시도 3-4: 단계별 제거 (Sequential Halving 변형)
- **문제**: 제거된 후보의 LLR 드리프트, valid 후보 조기 제거
- 후보 간 evidence 공유로 상관계수 0.50 → 이론치보다 제거율 높음
- correlation 때문에 valid이 운 나쁘면 여러 invalid에 동시 패배

### 시도 5: Always-query-top-1
- **문제**: argmax trap 재발 — invalid 후보가 운 좋게 1위 유지 → budget 전소
- Python max() tie-breaking으로 valid이 뒤쪽 index면 도달 불가

### 시도 6-7: 고정 Phase + Duel
- **문제**: 이론적 per-byte error 0.7%로 계산했지만 실제 ~5%+
- selection bias 미반영: Phase 1 생존 invalid은 "운 좋은 놈들" → 이후 phase에서도 유리
- 이론적 분석이 너무 낙관적이었음

### 시도 8: 독립 LLR (ChatGPT 버전)
- **문제**: 독립 추적이라도 ranking 자체는 동일 score 기반
- 조기 폐기(p<0.68)는 명백한 실패만 감지, 미묘한 오류는 통과
- 0.93^32 ≈ 10% → 5회 병렬 실행도 전부 실패

### 공통 실패 원인
1. **바이트당 정확도를 과대평가** (이론 99% vs 실제 75-85%)
2. **selection bias 무시** — 생존한 wrong arm은 평균보다 강함
3. **재시도 미활용** — 한 번에 성공하려고 함 (불가능)

---

## 현재 솔버: 왜 성공하는가

### 알고리즘: Adaptive Top-2 with LLR

```
1. 스크리닝: 16개 후보 × 4쿼리 = 64쿼리
   → 각 후보의 초기 LLR 추정

2. 적응적 집중: 나머지 ~306쿼리
   → 매 라운드 LLR 상위 2개 후보에 쿼리
   → 틀린 후보: 쿼리할수록 LLR 자연 하락 (-0.081/query)
   → 맞는 후보: 언젠가 top-2에 진입 → 최종 duel 승리

3. 최종 선택: LLR 최대값
```

### Adaptive Top-2가 SH보다 우월한 이유

| 항목 | Sequential Halving | Adaptive Top-2 |
|------|-------------------|----------------|
| 스크리닝 오류 | Round 0에서 정답 제거 → 복구 불가 | 틀린 후보가 자연 하락 → 정답 자동 부상 |
| 바이트당 정확도 | ~75% | ~86% |
| Selection bias | 생존 wrong arm이 유리해짐 | Wrong arm을 계속 쿼리하므로 자연 교정 |
| 자기 교정 | 없음 (제거는 돌이킬 수 없음) | 있음 (LLR 기반 재정렬) |

**핵심 차이: "제거" vs "자연 하락"**

- SH: 7쿼리 후 하위 8개 **영구 제거** → 정답이 제거되면 끝
- Adaptive: 틀린 후보가 top-2에 올라와도, 쿼리하면 LLR이 점점 떨어짐
  - 틀린 후보 1개 burn에 ~10-20쿼리
  - 6개 burn해도 ~120쿼리, 나머지 ~250쿼리로 최종 duel
  - 최종 duel에서 z ≈ 2.4+ → 정답 승리 확률 >99%

### 성공 전략: 재시도

- 바이트당 86% → 0.86^32 ≈ 0.7% per attempt
- **한 번에 성공하는 것은 불가능** — 이것이 핵심 깨달음
- 대신 수백 번 재시도: 500회 시도 시 P(성공) ≈ 97%
- 로컬: ~300회 = ~2분
- 서버: ~300회 = ~수시간 (병렬 실행 권장)

---

## 실험 결과

### 바이트당 정확도 비교 (byte 15, N=1000, budget=370)

| 전략 | 정확도 |
|------|--------|
| Uniform (제거 없음, 23쿼리×16후보) | 59.0% |
| SH (12,8,10) | 75.1% |
| SH Heavy R0 (18,5,5) | 67.0% |
| SH 5-round (6,6,6,8) | 73.0% |
| Adaptive Elimination | 58.6% |
| **Adaptive Top-2 (screen=4)** | **85.7%** |

### 전체 솔버 (32바이트, cascade 포함)

- 1000회 시도: 2회 성공 (0.2%)
- 317회 시도: 3회 성공 (0.95%) — 운 좋은 배치
- 평균 ~500회 시도에 1회 성공

### 로컬 성공 확인

```
SUCCESS #1 on attempt 216 (88s)
SUCCESS #2 on attempt 312 (126s)
SUCCESS #3 on attempt 317 (128s)
Message: dab444d96828292b02fd7aa61273667c
Recovered: dab444d96828292b02fd7aa61273667c ← 완벽 일치
```

---

## 파일 구조

| 파일 | 설명 |
|------|------|
| `solver.py` | **최종 솔버** (로컬/서버 겸용, 자동 재시도) |
| `13423_*.py` | 서버 원본 코드 |
| `failed_attempts/NOTES.md` | 시도 1-8 상세 기록 |
| `test_adaptive.py` | 전략별 바이트 정확도 비교 |
| `measure_accuracy.py` | 캐스케이드 유무별 정확도 측정 |
| `test_strategies.py` | SH vs Adaptive vs Uniform 비교 |
| `tune_sh.py` | SH 스케줄 그리드 서치 (결론: SH 최대 80%) |
