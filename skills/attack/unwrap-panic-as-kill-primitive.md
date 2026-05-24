---
name: unwrap-panic-as-kill-primitive
description: Rust/tokio peer가 server error response를 `panic!` 처리하면 의도적 error 유발로 peer task kill. tokio task panic → connection drop → 다른 멤버 죽일 수 있는 primitive
type: skill
---

# Unwrap-Panic as Kill Primitive

## 패턴
Rust/tokio 구현체가 server response를 처리할 때:

```rust
async fn send_raw_message_to(&mut self, to: &str, message: &str) -> Result<()> {
    self.send(ClientCommand::SendMessage(to.into(), message.into())).await?;
    match self.recv_cmd().await? {
        ServerCommand::Acknowledged => Ok(()),
        cmd => panic!("Unexpected command from server {cmd:?}"),  // ← 함정!
    }
}
```

이 함수가 `Result<()>` 반환하니 보통 caller가 `await?`로 처리하지만, 실제로는 **panic**이 먼저 터짐. server가 `ErrorContinue("No such user")` 같은 error 보내면 → panic → tokio task die → drop TcpStream → connection close → server-side user disconnected.

## 공격 시나리오
**1. Direct: peer가 send_dm_to(fake_user, ...) 호출하게 유도**

forged Commitments + NGS phase에서 bot이 fake user에게 DM 시도. server "No such user" → ErrorContinue → bot panic → die.

**2. Custom error responses**

다른 트리거: 
- 채널 미참여 user에게 MSG → "Not in channel"
- 잘못된 인자로 명령 → ParseError

## 적용 절차 (peer가 사용자 list 순회하며 send_dm_to 호출하는 경우)

1. **fake user를 user list에 강제 삽입**
   - protocol이 user list를 받는 메시지 (Commitments, Begin, etc.) 가 있으면 위조 페이로드로 fake user 포함 list 주입.

2. **bot이 그 list 순회하게 만들기**
   - NGS phase처럼 peer가 list iter 후 각 user에게 DM 보내는 phase 트리거.

3. **panic 확인**
   - 잠깐 뒤 PEEK → bot 없으면 성공.
   - Live latency: ~7-8s wait 후 확인.

## 코드 골격
```python
# Forged Commitments with fake user in member list
forged_users = [target_real_bot, *([me] * 6), "fake_user_xxx"]
c.send(f"MSG {CHAN} COMMITMENTS {ident} {q} {g} {commits} {','.join(forged_users)}")
# Drive protocol forward (PROPOSE/NUC/NUR/Begin) so bot enters NGS phase
...
# After Begin → bot does for u in forged_users: send_dm_to(u, NGS_msg)
# Reaches fake_user → server ErrorContinue → bot panic
time.sleep(8)  # bot's tokio_sleep(3s) + NGS iteration + panic propagation
active = peek_users()
assert target_real_bot not in active
```

## 주의
- **Self-DM은 enqueue_self**: peer 본인에게 DM은 보통 local enqueue로 우회 → panic 안 됨. fake user는 서버 쪽 lookup 실패해야 함.
- **send_dm_to wrapper**: panic이 어디서 일어나는지 확인. wrapper가 Result로 흡수하면 동작 안 함.
- **Server 측에서 channel 차단**: 모든 peer가 동일 channel이면 한 peer panic은 broadcast의 다른 subscriber에는 영향 X. 우리 자신만 peer kill.
- **broadcast Lagged subscribe panic**: `tokio::sync::broadcast::channel(N)` + `Ok(msg) = ... else => unreachable!()` 패턴은 우리도 lag시 같은 함정에 빠짐. `tokio-broadcast-lag-panic` 참고.

## 식별
다음 코드 패턴 보이면 의심:
- `cmd => panic!(...)` in async receive handler
- `.recv().await?` followed by exhaustive match without graceful `Err`/`continue` branch
- `expect("...")` / `unwrap()` on network ops without retry

## 트리거 키워드
- Rust/tokio CTF challenge with networked protocol
- "We are dropping like flies" / panic threshold
- 다른 client/bot/peer를 kill해야 진행되는 challenge

## 참고
- The Black Talon (DEF CON Quals 2026 / BBB CTF), `sources/client/src/connection.rs:148-155`
- Related: `tokio-broadcast-lag-panic` (server-side panic for connection drop)
