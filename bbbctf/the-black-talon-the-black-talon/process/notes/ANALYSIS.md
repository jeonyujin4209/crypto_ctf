# The Black Talon — 분석 노트

작성일: 2026-05-24
챌린지: DEF CON CTF Quals 2026 (운영팀: bbb=Benevolent Bureau of Birds)
연결: `ncat --ssl the-black-talon.ctfwithbirds.com 1337`
인증: PoW (Argon2id, difficulty 17) → game start

## 챌린지 구조

### 시나리오
- IRC-style TCP 서버 (Rust + tokio)
- 50개 bot + 1 sheriff + 우리(protagonist) 모두 동일 saloon 채널
- Sheriff가 64-char alphanumeric **secret**을 5-out-of-10 Pedersen VSS로 commit
- 우리는 `--force-user`로 강제로 committee에 들어감 (key 1-10 중 하나에)
- 5분 안에 secret 추측 → orchestrator stdin → flag 출력 (stderr → stdout으로 forwarding됨)

### Crypto setup
- 513-bit safe prime p, q = (p-1)/2 (512-bit prime)
- g = 2, p mod 8 ∈ {1, 7}
- f(x) = secret + Σ a_i·x^i mod q, degree 4, a_1..a_4 ∈ [q/2, q) random
- Commitments c_i = g^a_i mod p, broadcast
- Shares f(1..10) DM'd to 10 committee members

### Recommittee (proactive resharing)
- 각 100s 마다 bot timer fires; share_info.users.all_active 실패 시 Propose
- Phases: Propose → NUC (Pedersen commit to random u64) → NUR (reveal) → Begin (chooses new user via XOR) → NGC (broadcast r/n commits) → NGS (DM r/n shares) → BR (broadcast t_share) → PR (broadcast t)
- 각 j: r_j(x) random degree-4 with r_j(0)=my_r_j, n_j(x) with n_j(0)=q-my_r_j
- `g^t == c_0 · prod_j(g^my_r_j)` (empirically 검증됨)
- 새 polynomial f'(x) = secret + Σ_j b_j(x) where b_j(x) = n_j(x) - n_j(0)

### 주요 보안 속성
- 1-collusion (single share holder = 우리)는 standard PSS security로 보호
- 정보 이론적으로 secret 복구 불가 — 5 evaluations of single polynomial 필요
- DLP-hard: g^secret = c_0, 512-bit prime, infeasible

## 시도한 공격들

### 1. 단순 RELEASE 시도 (실패)
- Bot의 RELEASE handler가 `info.initiator != msg.from`을 체크
- Sheriff disconnect 후 누구도 sheriff name으로 RELEASE 불가
- 우리 이름은 protagonist (고정), sheriff name과 다름

### 2. Forged Begin to non-committee bot (실패)
- 비-committee bot에게 forged Begin 보내면 share_info{initiator=us} 생성
- 하지만 share=None → RELEASE 해도 빈 share
- Share DM으로 share 설정 시도 → commitments=empty이므로 value=0만 valid → useless

### 3. Commitments overwrite로 initiator 변경 (실패)
- 같은 ident으로 우리 Commitments 보내면 db.insert가 OVERWRITE
- BUT `share: Default::default()` → share 항상 wipe됨
- 새 initiator 설정 가능하지만 share 잃음

### 4. BR/PR/NUR no-auth abuse (효과 제한)
- BlindedRelease, PublicRelease, NewUserReveal에 msg.from 체크 없음 (검증됨)
- 임의 t 주입 가능하지만 결과적으로 새 polynomial의 constant term을 corrupt할 뿐
- secret 복구에 직접 도움 안 됨

### 5. Self-duplicate in new_users (부분 성공)
- Begin's `recomm.new_users.add(user)`에 dedup 없음
- user==old committee member면 그 user가 new_users에 중복됨
- 그 user는 N DMs을 2번 받음 → second NGS triggers abort (n_shares[from_key] already set)
- **우리가 chosen new user면 raw TCP라 abort 안 함, 2 evaluations 받음**

### 6. Forged Commitments with non-existent user (검증됨 ✓)
- Send `COMMITMENTS ident commits users=[bots, fake_user]`
- Targeted bots overwrite share_info, users 리스트에 fake_user 포함
- 이들의 `all_active` 체크 fail → 100s timer fire 시 Propose 발사
- **로컬 테스트 확인됨**: 5개 forged bot이 Propose 보냄

### 7. DM-flood broadcast lag DOS (실패)
- 2000 DMs in 0.34s 보냈는데 target bot이 죽지 않음
- Tokio broadcast channel은 빠르게 process함 (or capacity 충분히 큼)
- Selective DOS for bot disconnection 어려움

## 검증된 수식

```
t = secret + Σ_j my_r_j (mod q)            # 활성 old members j
g^t = c_0 · Π_j g^my_r_j (mod p)            # 검증됨 ✓
f'(x) = secret + Σ_j (n_j(x) - n_j(0))      # 새 polynomial
new_share(key) = Σ_j n_j(key) + t           # = f'(key)
```

## 핵심 막힘

1-collusion에서 secret 복구는:
- **5+ evaluations of single polynomial 필요** (Lagrange interpolation)
- 우리가 chosen new user당 2 evaluations (1 inactive committee 가정)
- 여러 recommittee 가로질러 결합 불가 (각 polynomial 독립적)
- 4-5 consecutive "us-chosen" recommittees 필요 (확률 1/N each, N=active_users.len ≥ 35 panic_threshold)

수학적으로 가능하나 시간 budget (5min) 안에 확률 너무 낮음.

## 미 확인 / 시도 못한 attack vectors

### A. Cumulative position attack (구현 필요)
- 우리 chosen 시 share_info.users에 우리 1번 추가
- 여러 cycle 거쳐 우리 K positions 까지 누적
- K=4면 다음 recommittee에서 5 positions → secret 복구
- 확률: P(K≥4 in N tries) — 매우 낮음 (P=1/35 per try)

### B. Lattice attack on biased coefficients
- f(my_k) = secret + Σ a_i·my_k^i, a_i ∈ [q/2, q) biased
- Single equation in 5 unknowns + bounds — undetermined
- 추가 commitments로도 DLP-hard

### C. Custom send_raw_message_to panic 활용
- `panic!("Unexpected command from server {cmd:?}")` if non-ACK
- ErrorContinue 받으면 panic
- 어떤 path가 server를 비-ACK 응답 보내게 할지 명확하지 않음

### D. Recommittee chain with selective DM-flood
- DM-flood로 specific bot 죽이고 (broadcast lag) — 위 #7에서 실패
- 다른 DOS mechanism 필요 (e.g., 거대한 메시지로 stream OOM)

## 환경 정보

- Live server: `the-black-talon.ctfwithbirds.com:1337`
- Token expires: 2026-05-31
- 각 connection = 새 nsjail instance (300s time_limit)
- PoW takes ~45s, game ~240s effective
- Orchestrator info messages visible (stderr → stdout)
- Flag 출력 path: `info!(flag, ...)` (correct guess 시)

## 결론

- 표준 분석으론 1-collusion이 정보 이론적 안전
- D'Arco-Stinson PSS attack on commitment-to-0 schemes는 이 protocol에 매핑되긴 하나 명시적 algebraic recipe 못 찾음
- Implementation level bug도 line-by-line audit 후 분명한 것 못 찾음
- 챌린지가 정말 어렵거나 (Quals top-tier) AI가 놓친 specific insight 필요

## 파일 위치
- `solve/proto.py` — protocol helpers (b36 encoding, share validation, Lagrange)
- `solve/client.py` — raw TCP client
- `solve/scenario.py` — local test scenario
- `solve/exp_*.py` — empirical experiments
- `solve/live_*.py` — live server attack attempts
- `solve/local_attack.py` — DM-flood + forged Commitments local tests
- `live_v*.txt` — captured session logs
