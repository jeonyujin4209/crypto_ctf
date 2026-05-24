# tokio broadcast Lag → `unreachable!()` Panic

type: failure
tags: [rust, tokio, broadcast, race, server-panic, lagged]

## 실수 패턴

Rust server가 `tokio::sync::broadcast::channel(N)` (capacity N)로 client 간 메시지 분배. 각 client task가 `subscriber.recv()` 호출. `tokio::select!`:

```rust
let next_step = tokio::select! {
    cmd = reader.next_command() => match cmd { ... },
    Ok(msg) = subscriber.recv() => NextStep::Broadcast(msg),
    else => unreachable!(),
};
```

**함정**: `subscriber.recv()` returns `Result<T, RecvError>`. RecvError can be `Closed` 또는 **`Lagged(u64)`** (capacity 넘게 밀림). `Ok(msg)` 패턴은 Lagged 매치 안 함 → `else => unreachable!()` 도달 → **server task panic** → 그 client connection drop.

## 발생 조건

- 우리 client task가 broadcast로 들어오는 메시지를 처리 (= writer.send_command(...))하는 속도가 incoming rate보다 느림
- N (capacity) 초과 lag → Lagged error → panic
- TLS 핸드셰이크, 네트워크 지연, 우리 측 buffer 부족 등으로 흔히 발생

## 사례 (The Black Talon)

`network/src/main.rs` capacity = 1024. R cycle에서 NGS 메시지가 ~200/peer × 50 bots = 10000 broadcasts → 1024 capacity 빠르게 초과.

우리 TLS client가 read 속도 못 따라가면 server-side subscriber lag → 우리 task panic → 우리 connection 끊김. Live attack에서 K=3-4 도달 후 자주 발생.

## 영향

- **공격자 입장 (이번 케이스)**: 의도치 않게 우리 자신 연결 끊김. attack 진행 불능 → 재시도.
- **방어자 입장**: 단일 slow client로 server task panic 유발 = DoS vector.
- **공격자 활용 (다른 케이스)**: 특정 target user의 subscriber를 의도적으로 lag 시켜 그 user의 task 죽이기 가능 (broadcast 폭주 인위적 유발).

## 해결 (회피)

우리 client read 속도 향상:
1. **TLS recv 빠르게**: thread / async로 socket buffer 비우기.
2. **Filter at reader**: 우리가 처리할 메시지만 즉시 queue, 나머지는 drop.
3. **Reduce traffic**: NGS 등 broadcast 줄이기.
4. **Capacity 키우기**: server-side 코드 수정 가능하면 capacity 늘림.

## 공격으로 활용

상대를 lag 시키려면:
- 대량 broadcast 짧은 시간에 발생시켜 모든 subscriber 동시 처리 부담.
- target만 lag 시키긴 어려움 (모든 subscriber 동시 push). 우리가 같이 lag될 위험.

## 범용 교훈

Rust async network code review 시:
1. `subscriber.recv()` 결과를 `Ok(msg)`만 매치하는 select 의심.
2. `else => unreachable!()` 안전 검토.
3. Lagged 처리 누락 시 panic safety 깨짐.
4. broadcast capacity vs 예상 message rate 비교.

## 식별 sig
- Rust server with `tokio::sync::broadcast::channel(N)`
- `tokio::select! { ... Ok(msg) = subscriber.recv() => ..., else => unreachable!() }`
- 50+ peer + 고빈도 broadcast protocol (MPC, gossip, etc.)
- Connection이 "이유 없이" 중간에 drop

## 참고
- The Black Talon: `sources/network/src/main.rs:163-170`
- broadcast tokio docs: https://docs.rs/tokio/latest/tokio/sync/broadcast/struct.Receiver.html#method.recv
