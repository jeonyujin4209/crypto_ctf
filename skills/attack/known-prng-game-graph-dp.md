---
name: known-prng-game-graph-dp
description: PRNG state 복원 후 → 미래 스트림 전체 예측 → graph DP로 최적 경로 선택. "기댓값 최대화"가 아니라 "달성 가능한 최대 wins 경로" 탐색.
type: skill
---

## 핵심 통찰

PRNG state를 알면 **미래가 완전히 결정론적**. 더이상 확률 문제가 아님:
- ❌ 잘못된 프레이밍: "각 라운드 win probability 최대화 → E[wins] ≈ 766" → 불확실한 기댓값
- ✅ 올바른 프레이밍: "이 고정된 스트림에서 정확히 어떤 행동 시퀀스가 ≥800 wins 경로를 만드나?" → deterministic 탐색

greedy (54% win rate) vs graph DP (64%+) 차이가 이 통찰에서 나옴.

## 알고리즘 (Graph DP)

스트림 위치를 node로, 라운드를 edge로 하는 DAG에서 최적 경로 탐색:

```python
def run_dp(arr, initial_wins, initial_rounds, total_rounds, win_threshold):
    """
    arr: 알려진 미래 draws. arr[0] = 현재 라운드 첫 번째 카드 (이미 딜됨).
    반환: (max_wins, path_tuple) or (None, None)
    """
    def how_many(threshold, offset):
        """딜러 시뮬레이션: arr[offset]부터 그려서 total > threshold 되는 시점."""
        total = 0.0
        while total <= threshold:
            if offset >= len(arr): return False, offset
            total += arr[offset]; offset += 1
        return total >= 1.0, offset  # True=dealer bust=player wins

    def get_edges(offset):
        """offset에서 가능한 모든 행동(서거나 히트) 열거."""
        total = arr[offset]
        while total < 1.0:
            win, dst = how_many(total, offset + 1)
            yield (offset, 1), (win, dst)   # stand here
            offset += 1
            if offset >= len(arr): break
            total += arr[offset]
        yield (offset, 0), (False, offset + 1)  # bust

    def choose(old, new):
        """더 많은 wins 선택, 동점이면 더 적은 rounds 사용."""
        if old is None: return new
        return old if (old[0], -old[1]) >= (new[0], -new[1]) else new

    leaf = None
    dic = {0: (initial_wins, initial_rounds, (b'', None))}
    while dic:
        i = min(dic.keys())
        wins, rounds, parent = dic.pop(i)
        for code, (win, dst) in get_edges(i):
            # code = (last_card_offset, 1_if_stand_0_if_bust)
            # code_bin: '\n'=hit, 's\n'=stand
            code_bin = b'\n' * (code[0] - i) + b's\n' * code[1]
            next_state = (wins + int(win), rounds + 1, (code_bin, parent))
            if rounds + 1 == total_rounds:
                leaf = choose(leaf, next_state)
            else:
                dic[dst] = choose(dic.get(dst), next_state)

    if leaf is None or leaf[0] < win_threshold:
        return None, None
    return leaf[0], leaf[2]

# path 역추적
def get_commands(path_tuple):
    code, parent = path_tuple
    cmds = []
    while parent is not None:
        cmds.append(code)
        code, parent = parent
    return b''.join(reversed(cmds))
```

## 서버 프로토콜 통합

1. Phase 1: threshold 전략으로 624 floats 수집. **break 시점은 반드시 새 라운드의 첫 카드 직후** (서버가 hit/stand 대기 중).
2. Z3로 state 복원. `arr = [draws[-1]] + [r.random() for _ in range(10000)]`
3. DP 실행. 성공이면 command bytes를 **한 번에 전송**: `conn.send_raw(commands)`

서버가 sequential하게 `input()`을 호출하므로 bulk send 가능.

## 서버 입력 인코딩

```
'\n'   → hit  (empty line = not 's' = continue)
's\n'  → stand
```

`code_bin = b'\n' * hits + b's\n' * (1 if stand else 0)`

bust 시: 마지막 카드 후 서버가 input() 안 호출 → 그 카드에 대한 명령 없음. hits개만 전송.

## 성공 확률

- 약 80%: 랜덤 스트림에서 최적 경로가 win_threshold 이상 (20%는 경로 없음 → 재시도)
- greedy는 기댓값이 800 미만 → 성공 확률 ~0%. DP 필수.
- arr 길이 = 10000이면 1100+라운드 충분히 커버.

## 실전 예시 (Probability — SEETF 2022)

- 1337라운드, 800 wins 필요 (59.84% 달성 요구)
- Phase 1: ~181라운드 (threshold 0.57), ~86 wins
- DP로 1156라운드에서 739+ wins = 825+ total
- 성공 확률 ~80%. 2번째 시도에서 SEE{1337_card_counting_24ca335ed1cabbcf}
