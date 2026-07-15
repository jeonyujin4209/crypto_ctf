# Progress Update

작성: 2026-05-24, ANALYSIS.md 이후

## 새로 검증된 사실

### ✅ Forged Commitments + NGS panic = bot kill (검증됨)
로컬 docker에서:
- `COMMITMENTS new_ident, users=[5 victims, fake_user, us]` 보냄
- Share DM으로 각 victim에게 share 설정
- Propose, NUC, NUR, Begin → bots NGS phase에서 fake_user에 DM 시도
- Server returns "No such user" → bot's send_raw_message_to panics → tokio task ends → bot disconnects
- **5명 한꺼번에 죽임 확인**

### ✅ 우리가 chosen new user면 recommittee 완료 (검증됨)
- 다른 bot이 chosen이면 self-duplicate abort 발생
- 우리는 raw TCP라 abort 안 함
- new_users에 우리가 K+1 positions (us at K positions in old + add(us))
- N DMs 받음 → f'(key_i) for each i 계산 가능

### ✅ NUR subset 선택으로 r XOR 부분 통제 (검증됨)
- 우리가 K positions이면 2^K-1 non-empty subsets
- Bots' XOR + 우리 subset XOR 가지고 r mod N 다양한 값 만듦
- P(any subset matches idx(us)) ≈ (2^K-1)/N

### ✅ R1 cycle 성공 (로컬에서 확인)
- cycle 12에서 us chosen, 2 evals at keys [1, 6]
- f'(1) 과 f'(6) 계산됨

## 핵심 막힘

### R2 cycle을 트리거하려면 bot 죽여야
- R1 완료 후 new committee = ['vulture', 4 alive, 'vulture'] (6 entries)
- 모두 alive → all_active = true → Propose abort
- 1개 더 죽여야 함

### Kill 1 bot 메커니즘 미완성
- Forged Commitments with users=[target, us×4, fake] 필요
- 5 entities for rs.len ≥ 5 (threshold)
- NUR subset으로 user=us 만들기 → target's Begin acceptance
- 시간 budget tight (R2-R5 4 cycles + kills = ~80s)

## 이론적 path-to-solve

1. Initial: kill 5 committee bots (~10s).
2. R1 cycle: 1/N chance per attempt (K=1, 1 non-empty subset). 평균 ~45 attempts × 4s = 180s. ← 큰 부담
3. R2-R4: K=2,3,4. P per cycle = (2^K-1)/N. R5: K=5에서 우리 chosen → 5 evals → recover secret.

Total expected time: 200-300s. 5분 game budget 안에 가능하지만 tight.

## 시도 못한 path

- **Lattice attack on 2 partial evaluations of f' + sheriff_commits structure**: K=1만으로도 2 evals 받음. 5 unknowns + 2 equations + commits (DLP-hard) — 부족하지만 시도 가치 있음
- **Replicated NUR via collision oracle**: NUR HashSet uniqueness 우회
- **Begin handler edge cases**: user 필드에 특수값 (fake / known dead) 보내 어떻게 처리되는지 확인

## 코드 위치
- `solve/local_full_attack.py` — 현재 attack 구현
- `solve/local_kill_test.py` — kill 메커니즘 verify
- `solve/live_v*.py` — live server attack 시도들
- `ANALYSIS.md` — 전체 분석

## Honest verdict

**기술적으로 가능한 attack을 찾았으나 구현 incomplete.** K=1 R1 cycle 성공 검증. R2+ 사이클이 kill mechanism 필요 → 시간 budget 안에 가능할지 불확실. 추가 1-2시간 작업으로 완성 가능할 것 같음.

**Live server에서 한번 successful run 하려면**:
- Total expected ~200-300s game time
- PoW ~45s
- 240s game budget
- Cutting it close — may need multiple sessions
