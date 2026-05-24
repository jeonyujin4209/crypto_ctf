---
name: live-pow-budget-calibration
description: kCTF-style PoW (Argon2id) 시간 variance 30~100s. game timeout 합쳐서 effective budget 가변. retry 시 PoW 시간 측정 후 deadline 동적 계산. nsjail 300s에서 마진 25-30s 남기기
type: tool
---

# Live PoW Budget Calibration

## 패턴

kCTF style challenge:
- TLS connect → PoW challenge 받음 (e.g., `a2id.v2.17.<hex>`)
- Argon2id difficulty 17 (또는 다른 값) 풀어 solution 송신
- 그 후 game starts
- nsjail이 connection 전체에 time_limit (보통 300s)

**PoW 시간 variance**:
- argon2id는 cost-bounded이지만 counter brute force라 운에 따라 다름
- 측정값 (difficulty 17): 27~97s (3.5x 차이)
- 평균 ~60s, std ~25s

**Budget**:
- nsjail 300s
- PoW: 30~100s
- setup (orchestrator child spawn, prompt 읽기): 5s
- post-game (GOODBYE + cleanup + read_line): 25-30s
- **Game phase effective budget = 300 - PoW - 5 - 30 = 165 ~ 235s**

## 권장 코드 패턴

```python
# PoW phase
pow_chal = ...  # parse from initial banner
t_pow_start = time.time()
sol = solve_pow(pow_chal)
pow_duration = time.time() - t_pow_start
print(f"[+] PoW {pow_duration:.1f}s")
c.send(sol)

# Game phase deadline 동적 계산
game_start = time.time()
NSJAIL_LIMIT = 300
POST_GAME_RESERVE = 30  # GOODBYE + cleanup + read_line + flag wait
CYCLE_DEADLINE = game_start + (NSJAIL_LIMIT - pow_duration - POST_GAME_RESERVE)
# 또는 fixed conservative: game_start + 220 (works for PoW up to ~50s)
```

## 시도/실패 데이터 (The Black Talon)

| Run | PoW | Game | Result |
|-----|-----|------|--------|
| live6 | 70s | 238s | secret 추출 OK, but post-game timeout (308s total) — flag 못 받음 |
| live10 | 84s | 117s (panic) | conn lost |
| live13 | 27s | 186s | full success |
| live22 | 33s | 210s | **FULL SUCCESS — flag captured** |

**관찰**: PoW < 50s + game < 220s + post-game < 30s 합쳐서 ~300s 안에 들면 success. PoW 80s 이상이면 game phase 시간 압박 심함.

## Retry 전략

1. PoW 시간을 첫 측정 시 출력 → 100s 이상이면 그냥 재시도 고려 (script 재시작).
2. Game phase에서 매 R cycle마다 elapsed 모니터링 → deadline 임박하면 K_new 미달이라도 partial recovery 시도.
3. 각 run은 stochastic. 5-10번 시도해서 한번 successful run.

## 주의
- nsjail time_limit이 client 측에서 보이지 않음. challenge README나 source에서 확인 (`time_limit: 300`).
- PoW variance는 단일 hex challenge에 대한 brute force 운. 다른 challenge는 다른 difficulty 사용.
- 재연결마다 PoW 새로 풀어야 함 (challenge 다름).

## 코드: PoW solver subprocess timing

```python
def solve_pow(chal):
    t0 = time.time()
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal],
                       capture_output=True, text=True, timeout=300)
    print(f"[+] PoW solved in {time.time()-t0:.1f}s")
    return r.stdout.strip()
```

## 트리거 키워드
- kCTF nsjail challenge
- `a2id.v2.<difficulty>.<hex>` (Argon2id PoW format)
- "PoW", "proof of work", "Argon2"
- 시간 budget tight한 attack chain

## 참고
- The Black Talon: `bbbctf/the-black-talon/solve/live_v5.py`
- POW solver template: `C:\Users\UserK\AppData\Local\Temp\bbb_pow.py` (kCTF standard)
