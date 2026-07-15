# The Black Talon — SOLVED ✅

- **대회**: DEF CON CTF Quals 2026 (운영: BBB — Benevolent Bureau of Birds)
- **분야**: Crypto (5-of-10 Pedersen VSS + proactive resharing) / Rust+tokio 네트워크 서버
- **연결**: `ncat --ssl the-black-talon.ctfwithbirds.com 1337` (서버는 현재 종료됨)

## 🏁 Flag

```
bbb{cavalcade_of_beggars_and_thieves:r6RfIwRESjd3RXMpEhFHhYGaKlN0iIeWNVvlXaeCqpBERMhi7BK_wMjnkWWapZNDMmsrN93gxK6hn--j1sNLYb5Qc_aZiVfm2TM}
```

> *"Every ghost in this town knows your name now---the flag is yours, for better or worse."*

라이브 서버에서 게임 시간 약 **213초** 만에 secret 복구 → 제출 성공.
원본 캡처: [`solve/output.log`](solve/output.log) (마지막 줄).

## 챌린지 요약

IRC 스타일 saloon 채널에 50 bot + 1 sheriff + 우리(protagonist)가 모여 있다.
Sheriff가 64자 secret을 **5-of-10 Pedersen VSS**로 commit하고, 주기적으로
**proactive resharing(recommittee)** 를 돈다. 우리는 `--force-user`로 committee의
한 자리(key 1–10)에 강제로 들어가 있고, 5분 안에 secret을 복구해 orchestrator에
제출하면 flag가 나온다.

1-collusion(share 1개 보유)은 정보 이론적으로 안전해야 하지만 — degree-4
polynomial의 evaluation은 **5개**가 있어야 Lagrange 보간이 가능하다 — 구현 버그
체인으로 우리가 **한 committee 안에서 5개 자리**를 차지해 5 evaluation을 뽑아낸다.

## 공격 (cumulative K-position attack)

1. **봇 죽이기 — Forged `COMMITMENTS` + NGS panic**
   존재하지 않는 `fake_user`를 포함한 users 리스트로 `COMMITMENTS`를 보내면 대상
   봇들이 share_info를 덮어쓴다. 이후 NGS 단계에서 봇이 fake_user에게 DM 시도 →
   서버 `No such user` → 봇의 `send_raw_message_to`가 panic → 봇 disconnect.
   → recommittee(Propose)를 강제 트리거.

2. **우리가 new user로 선택되게 만들기 — self-duplicate + NUR subset XOR**
   `Begin`의 `new_users.add()`에 dedup이 없다. 새 user는 XOR(모든 NUR reveal)
   `mod N`으로 정해지는데, 우리가 K개 자리를 차지하면 우리 NUR를 넣을/뺄
   `2^K−1`개의 non-empty subset이 생긴다. 그중 XOR 결과가 우리 index가 되는 subset을
   골라 reveal하면 우리가 chosen new user가 된다. 우리는 raw TCP라 중복 DM에도
   self-abort하지 않고 새 polynomial `f'`의 evaluation을 받는다.

3. **K 누적 (1→2→3→4→5)**
   chosen될 때마다 committee 안 우리 자리가 하나씩 늘어난다. 자리가 많아질수록
   다음 cycle의 성공 확률 `(2^K−1)/N`도 커진다.

4. **K=5에서 secret 복구**
   degree-4 `f'`의 evaluation 5개 → `lagrange_at0` → secret.
   (`f'(x) = secret + Σ_j (n_j(x) − n_j(0))`, `new_share(key) = Σ_j n_j(key) + t`)

5. **제출 — GOODBYE 후 race-safe resend**
   secret을 orchestrator stdin에 반복 전송해 in-thread 종료 타이밍 race를 이긴다 →
   orchestrator가 flag를 `info!` 로그로 출력.

## 파일 구조

```
README.md              이 문서 (정답 writeup)
solve/
  solve.py             ★ 최종 solve — 라이브 서버 공격 (원래 live_v5.py)
  proto.py             프로토콜 헬퍼 (b36 인코딩, share 검증, Lagrange)
  output.log           ★ 승리 세션 로그 — 마지막 줄에 flag (원래 live_v5.txt)
sources/               챌린지 원본 (Rust: client / network / orchestrator / common) + Docker/Justfile
process/               풀이 과정 아카이브
  notes/               ANALYSIS.md · PROGRESS.md · FINAL_REPORT.md
                       (※ FINAL_REPORT/PROGRESS는 성공 직전 작성돼 "미완성"으로 기록된 outdated 문서)
  code/                로컬 재현 + 실험 반복 (local_full_attack.py, exp_*, live_v2~v4 등)
  logs/                중간 캡처 로그 (atk*_log, live_v2~4.txt 등)
```

## 재현 메모

- 서버는 대회 종료로 닫힘. 로컬 재현은 `sources/`의 Rust 서버를 `just`/docker로
  띄우고 `process/code/local_full_attack.py`(로컬 프로토콜 공격)로 검증한다.
- `solve.py`는 라이브 전용: TLS + JWT 토큰 + PoW(Argon2id, difficulty 17)가 붙어 있다.
  PoW 솔버는 `bbb_pow.py`라는 외부 임시 스크립트로 호출했고 temp에서 삭제됨 —
  재현 시 동등한 Argon2id 솔버로 대체 필요.
