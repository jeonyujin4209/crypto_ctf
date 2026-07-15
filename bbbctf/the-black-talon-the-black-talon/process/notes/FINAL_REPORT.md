# The Black Talon — 최종 보고

작성: 2026-05-24

## 결론

**공격 메커니즘 작동 확인됨, 신뢰도 부족으로 일관된 풀이 미달성**

atk9 실행에서 R1→R2→R3→R4 체인이 성공해 5 evaluations of single polynomial (keys [6,7,8,9,10]) 까지 도달.
하지만 ConnectionAbortedError로 final block 실행 전 종료, secret 미회수.

5번 이상 재시도했으나 R1-R3 단계에서 connection drop 또는 OOM (~6GB) 으로 중단됨.

## 검증된 attack pipeline

1. **Initial kill** (Forged COMMITMENTS + NGS panic): 1 committee bot 죽이기
2. **R cycle loop**: kill 1 → trigger Propose → NUC 6개 → NUR subset 선택 (XOR로 r mod N = my_idx 조작) → Begin with user=us → NGC + NGS → wait PR → into_share → 우리 K positions 증가
3. **K accumulation**: K=1→2→3→4→5 (5 cycles), 마지막 K=5에서 5 evaluations of new polynomial 받음
4. **Lagrange interpolation**: 5 points of degree-4 poly → secret

### atk9 timing (성공 사례)
- R1 (cycle 4): K=1→2, evals [9,10]
- R2 (cycle 8): K=2→3, evals [8,9,10]
- R3 (cycle 13): K=3→4, evals [7,8,9,10]
- R4 (cycle 20): K=4→5, evals [6,7,8,9,10] ← 5 evals!
- Total: 60s (cycle 20 elapsed ≈ -815s = +135s from start)

## 핵심 막힘 (왜 신뢰도 부족)

### 1. Server broadcast lag panic (line 169 in network/main.rs)
```rust
Ok(msg) = subscriber.recv() => NextStep::Broadcast(msg),
else => unreachable!(),
```
`tokio::sync::broadcast::channel(1024)` capacity. 우리 subscriber가 1024 msgs 뒤처지면 RecvError::Lagged → `else => unreachable!()` → server task panic → 우리 connection drop.

R cycle (NGC + NGS broadcast 폭주) 후 자주 발생.

### 2. Initial kill 신뢰도 ~30%
Forged COMMITMENTS + NGS 메커니즘은 작동하나 timing에 민감.
target의 NUR을 받지 못하면 fallback subset 사용 → kill 확률 낮아짐.

### 3. R cycle별 확률
- R1 (K=1): P = 2/N ≈ 4%/cycle. 평균 25 cycles, std 25 cycles.
- R2 (K=2): P = 4/N ≈ 8%/cycle. 평균 12 cycles.
- R3 (K=3): P = 8/N ≈ 16%/cycle. 평균 6 cycles.
- R4 (K=4): P = 16/N ≈ 32%/cycle. 평균 3 cycles.

R4까지 도달 = 평균 ~45 cycles × 3s/cycle = 135s. 600s 안에서 ~80% 성공.

### 4. Python OOM
실측: 5-7 cycles 후 Python 메모리 ~6 GB 도달. queue cap, filter 적용해도 동일.
원인 불명 (가설: Python's memory pool retention with high churn).
Process 종종 hang.

## 파일

- `solve/local_full_attack.py` — 메인 공격 코드
- `solve/proto.py` — protocol helpers
- `solve/client.py` — TCP client
- `solve/atk9_success_log.txt` — K=5 도달 로그 (cycle 20)
- `solve/atk21_log.txt` — R1+R2 도달 후 R3 drop 로그

## Honest verdict

**Mathematically possible, implementation不安定.** atk9의 K=5 도달이 attack chain 작동을 증명.
신뢰도 issue (connection drop, OOM)으로 final secret recovery 미완성.

5-10번 반복 실행 시 1-2번 성공 기대 가능. Live server 시도 시 PoW (~45s) + game (240s) 안에 운 좋으면 가능하나 not robust.

## 추가 발견된 문제 (atk22 분석)

R3 cycle에서 **MATCH가 발생해도 CHOSEN으로 이어지지 않는 패턴** 반복.
원인 추정: 우리가 capture한 bot NURs 일부 누락 → 우리가 계산한 X != bot이 계산한 X → bot들은 다른 user를 선택 → 우리 K position 증가 안 함.

K가 커질수록 더 많은 NGS 트래픽 → broadcast lag → NUR 메시지 일부 drop → 더 자주 실패.

## 가능한 개선 방향 (시도 못함)
- Connection drop 시 ReconnectAs로 재연결, state 유지
- Python 대신 Rust/Go로 client 재작성 (broadcast lag 회피)
- Multi-process: kill 전담 process + R chain process 분리
- Bot count 줄이기 (chal env 변경) — 50 → 35: broadcast 부담 감소
- NUR 수집 시간 늘리기 (현재 2.5s → 4-5s)
- NUR 수집 후 alive bot 수만큼 NUR 받았는지 검증, 안 되면 그 cycle abort

## 시도 횟수 요약
- atk1-atk6: 초기 디버깅
- atk7: cycle 36 R1 success, R2 BR 충돌 발견
- atk8-atk16: 다양한 fix 시도 (BR 제거, queue cap, filter)
- atk9: **R1→R4 full chain success, K=5 도달, connection alive throughout**
- atk21: R1+R2 success, R3 MATCH 후 drop
