# MPC Cycle: 부분적 randomness capture → False MATCH

type: failure
tags: [mpc, broadcast, randomness, xor, race, false-positive, cycle-waste]

## 실수 패턴

분산 프로토콜에서 N peers가 각자 random share를 broadcast (NUR/commit/etc.). final value (e.g., user 선출, threshold seed)는 `XOR(all_shares) mod N`.

**우리도 그 XOR을 계산**해 우리 전략 (subset selection, prediction) 짤 때, 일부 peer의 share를 못 받았으면 우리 XOR ≠ peer들이 계산한 XOR.

→ 우리는 "MATCH" 라고 판단해 다음 step (Begin/Commit/etc.) 보냄. 하지만 peer들은 다른 결과 계산 → 우리 메시지 reject / abort.

cycle 낭비. 다음 cycle도 같은 race 가능.

## 사례 (The Black Talon R3)

K_us = 3, alive bots = 7. Bot NUR 7개 받아야 우리 X = peer X. 

cycle 27: K=3 N=42 MATCH subset=0b0 my_idx=41 (우리 판단)
→ 우리 Begin(user=us) 보냄
→ bots compute different r → confirmed_user != us → abort
→ pr_t never arrives → 우리도 cycle 실패 처리

3번 연속 false MATCH 후에야 deduce. 디버깅 시간 손실.

**원인 분석**: K가 커질수록 NGS broadcasts 폭주 → 우리 socket recv 따라가지 못해 일부 NUR drop. live latency 추가 시 더 자주.

## 해결

**Wait until all peer NURs received** before computing XOR:

```python
alive_bot_count = sum(1 for u in committee if u != me and u not in dead_set)
nurs = {}
end_wait = time.time() + 6.0  # extended for high-K cycles
while time.time() < end_wait:
    if len(nurs) >= alive_bot_count: break  # early exit
    ln = c.recv(0.15)
    if ln is None: continue
    pm = parse_msg(ln)
    if not pm: continue
    _, frm, msg = pm
    if "NUR" in msg:
        nurs[frm] = parse_value(msg)

if len(nurs) < alive_bot_count:
    # Skip cycle. Don't false-MATCH.
    c.send("... JACCUSE abort")  # clear server-side state
    drain(0.3)
    continue
```

**핵심**: 부분 NUR로 XOR 시도하지 말기. 모두 받았을 때만 진행.

## 코드 패턴 (subset enumeration with min size)

또한 NUR count < threshold일 때 subset size로 보완:

```python
min_subset_size = max(0, THRESHOLD - len(nurs))
for bitmask in range(0, 1 << K):
    if bin(bitmask).count("1") < min_subset_size: continue
    ...
```

→ 받은 NUR + 우리 subset 합 ≥ threshold 보장.

## 범용 교훈

XOR/sum/MAC aggregation on broadcast:
1. **전체 peer set 식별**: 어떤 peer가 contribute하는지 명확히. dead peer 제외.
2. **count 검증**: received count == expected count. 부족하면 skip.
3. **timeout 신중하게**: too short → false MATCH. too long → cycle 시간 낭비.
4. **early exit**: count 만족 시 즉시 진행.

## 디버그 시그널

- "MATCH" 했는데 다음 step result (Begin response, PR, etc.) 안 옴.
- 같은 cycle에서 우리 X와 peer가 계산한 X가 다름.
- K 또는 broadcast traffic이 클 때 더 자주 발생.

## 식별 sig
- Distributed protocol with `XOR(random shares)` aggregation
- Per-cycle threshold check (e.g., `if rs.len >= PARAMS.threshold`)
- High-K MPC where our message rate is bottleneck
- Live network latency vs local docker (live 더 자주 실패)

## 참고
- 솔버: `bbbctf/the-black-talon/solve/local_full_attack.py` (lines 259-294, `alive_bot_count` validation)
- Related: `attack/pedersen-pss-k-position-accumulation`
