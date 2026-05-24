---
name: pedersen-pss-k-position-accumulation
description: Proactive Pedersen VSS recommittee에서 user duplication을 통한 K-position 누적 → 5 evaluations of same polynomial → Lagrange로 secret 복구
type: skill
---

# Pedersen PSS K-Position Accumulation Attack

## 패턴
Proactive Secret Sharing (PSS) protocol — 주기적 recommittee가 polynomial을 새로 생성하면서도 secret f(0)을 유지. Pedersen VSS 기반이면 다음 구조가 흔함:

- Committee members가 random `r_j(x)` (degree t) 생성, `n_j(x) = -r_j(x) + 2 stuff`, 공개 commit
- 새 committee member 선출: `r = XOR(all_NUR_values)`, `new_user = active_users[r % N]`
- 옛 멤버는 `share_old(key) + Σ r_j(key)` 를 broadcast (BR)
- `t = LagrangeRecover(BR_values)` 가 PR(public release)
- 새 멤버는 NGS(N) DM으로 받은 값 합산: `new_share(k) = Σ n_j(k) + t = f_new(k)` (새 polynomial 평가)

**Information theoretic security**: 1명만 collude하면 단일 evaluation만 알아 secret 복구 불가. 5명 evaluations of same polynomial이 필요.

## 공격 아이디어
**user duplication**: Begin handler가 `new_users.add(user)` 시 dedup 안 하면 같은 user를 여러 번 add 가능. 우리(공격자)를 chosen new user로 만들면 → 우리가 new committee에서 K positions를 점유.

다음 recommittee cycle에서 우리는 K positions로 K NUR/NGS 보내고, **chosen 되면** new committee에 또 1번 추가 → K+1 positions.

K=5 도달 시 한 cycle에서 5 distinct evaluations of same `f^(new)` polynomial → Lagrange recover secret.

## NUR XOR subset 조작
Begin 결정: `r = XOR(rs) mod N` 여기서 N = `active_users.len()`.

우리가 K NUC commits (random `s_i`) 만들면 K bits subset 선택 가능. 각 subset 마다:
- `r_subset = XOR(bot_NURs) XOR XOR(chosen us subset)`
- `r_subset mod N == my_idx_in_active` 가 되는 subset 찾기

P(any subset matches) ≈ `2^K / N`. K=1에서 2/N (~4%), K=4에서 16/N (~32%).

## Critical math: self-broadcast filter
Server가 self-DM filter하면 우리의 NGS(N) to ourselves를 **못 받음**. 우리 new_share reconstruction에 누락:

```python
n_per_key[k] = Σ (NGS N values received) at new pos k
# Server filtered our K self-DMs. 각 value = q - my_r_recomm. ADD manually:
n_per_key[k] += K * ((q - my_r_recomm) % q) % q

# Then:
fp_k = (n_per_key[k] + pr_t) % q  # = f_new(k)
```

자세한 derivation은 `failures/self-broadcast-filtered-math-correction` 참고.

## 적용 절차
1. **초기 kill**: committee bot 1개 죽이기 (`all_active` fail 유도). NGS-to-fake-user panic 사용 → `unwrap-panic-as-kill-primitive` skill 참고.

2. **R cycle loop** (K = `n_my_positions`, 시작 K=1):
   - PROPOSE 보내기.
   - K NUCs (random `s_i`).
   - **모든** alive bot NURs 받을 때까지 wait (불완전하면 false MATCH — `nur-all-bot-validation-mpc-cycle` 참고).
   - PEEK으로 `active_users` 받음, `my_idx`.
   - 2^K subsets enumeration → match found subset.
   - 선택된 subset의 NUR 발송 + Begin(user=us).
   - K our NGCs at our positions (constant polynomial: `r_commits=[g^my_r, 1, 1, 1, 1]`, `n_commits=[g^(q-my_r), 1, 1, 1, 1]`).
   - K × len(old_users) NGS R + K × len(new_users) NGS N to peers.
   - Wait PR. PR 받으면 chosen 성공.
   - `n_per_key[k] = sum NGS N values to us at k`, self-correction add.
   - K_new = K + 1. 다음 cycle을 위해 R kill 1 bot (sheriff_users에 새 dead 만들기).

3. **K=5 도달 시**: 5 evals at distinct k들 → Lagrange interpolation:
   ```python
   secret = lagrange_at0(list(this_evals.items())[:5], q)
   bs = secret.to_bytes(64, 'little').rstrip(b'\0')
   ```

## 코드 골격
```python
def r_cycle(K, sheriff_users, dead_set):
    # PROPOSE
    c.send(f"MSG {CHAN} RECOMM {ident} {nonce} PROPOSE")
    # K NUCs
    s_list = [randint(0, 2**64-1) for _ in range(K)]
    for s in s_list:
        c.send(f"... NUC {b36(pow(g, s, q))}")
    # collect bot NURs, abort if not all
    alive = sum(1 for u in sheriff_users if u != me and u not in dead_set)
    nurs = wait_for_nurs(alive)
    if len(nurs) < alive: return None  # skip cycle

    # subset enumeration
    X = xor_all(nurs.values())
    for mask in range(0, 1 << K):
        our_xor = xor_subset(s_list, mask)
        if (X ^ our_xor) % N == my_idx:
            target_subset = mask; break
    else:
        return None  # no match

    # send NURs + Begin + NGC + NGS, wait PR
    ...
    if pr_t is None: return None

    # Self-correction:
    self_n = (K * ((q - my_r_recomm) % q)) % q
    for k in n_per_key: n_per_key[k] = (n_per_key[k] + self_n) % q
    return {k: (sn + pr_t) % q for k, sn in n_per_key.items()}
```

## 주의
- **R polynomial 단순화**: constant `r_j(x) = my_r` 사용 (commits = `[g^my_r, 1, 1, 1, 1]`)으로 우리 NGS validation 자동 통과.
- **NGC validation 필수**: `r_commits[0] * n_commits[0] mod p == 1`. `r_c0 = g^my_r`, `n_c0 = g^(q-my_r)` → `g^q = 1` (g order = q).
- **BR collision 피하기**: 우리가 BR 보내면 우리 share key가 alive peer key와 충돌 → 그 peer의 BR이 abort. 안 보내는 게 낫다. 5+ alive bots가 BR하므로 threshold 만족.
- **Kill 대기 시간**: NGC 후 bot이 3s sleep + NGS iteration → 패닉까지 ~7s. drain 8s 이상.
- **`recomm.new_users.add(user)` dedup 없는지 확인**: 없으면 K-position accumulation 가능.
- **`is_new_user = !old_users.contains(myself)`**: 우리가 old_users에 있으면 false → "기존 멤버" 로직 작동. 우리가 새 user면 단순 add됨.

## 시간 budget
50 bot 환경, K=5 도달까지:
- R1 (K=1, P=2/N): 평균 N/2 cycles, ~30~60s
- R2 (K=2, P=4/N): 평균 ~15 cycles
- R3 (K=3, P=8/N): ~6 cycles
- R4 (K=4, P=16/N): ~3 cycles
- Total local: 60~80s. Live with latency: 150~210s.

## 트리거 키워드
- "proactive secret sharing" / "recommittee" / "resharing"
- Pedersen VSS commit + Lagrange recover
- `share + Σ r_j(key)` BR / public release pattern
- new_user 선출이 random (NUR XOR)인 protocol

## 참고
- The Black Talon (DEF CON Quals 2026 / BBB CTF). solve: `bbbctf/the-black-talon-the-black-talon/solve/live_v5.py`
- failure modes: `failures/self-broadcast-filtered-math-correction`, `failures/nur-all-bot-validation-mpc-cycle`
- 관련: `unwrap-panic-as-kill-primitive`, `tokio-broadcast-lag-panic`
