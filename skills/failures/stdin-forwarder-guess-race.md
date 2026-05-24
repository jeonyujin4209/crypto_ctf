# stdin Forwarder Race: Guess Lost to Broken Pipe

type: failure
tags: [orchestrator, nsjail, stdin, pipe, race, guess-submission, ctf-flow]

## 실수 패턴

CTF challenge가 orchestrator 형태로 wrap됨:
1. orchestrator (우리 TCP connection의 endpoint)가 child process (nc, game binary, etc.) 를 spawn.
2. orchestrator는 우리 stdin → child stdin, child stdout → 우리 stdout 으로 **forwarding thread** 실행 (game phase).
3. game 끝나면 child 죽고 forwarding thread 종료, orchestrator가 main thread로 돌아와 **자신의 stdin**에서 guess/flag-request 읽음.

**race 발생**: GOODBYE 직후 우리가 guess를 보내면 → forwarding thread가 아직 alive → 우리 데이터를 child stdin에 forward 시도 → child 이미 죽음 → broken pipe → forwarder는 데이터 drop하고 exit.

우리 guess가 사라짐. orchestrator의 read_line은 영원히 wait → nsjail timeout으로 connection killed → flag 못 받음.

## 사례 (The Black Talon)

```rust
fn connect_to_stdin_stdout(child_stdin, child_stdout) {
    let in_thread = std::thread::spawn(|| {
        loop {
            let len = stdin.read_available(&mut buf).unwrap();  // 우리 데이터 읽음
            ...
            match child_stdin.write(remaining) {
                Err(BrokenPipe) => break 'outer,  // child 죽으면 break (데이터 drop)
                ...
            }
        }
    });
    ...
}

// game phase 끝나면:
info!("What do you do?");
let guess = { let mut input = String::new(); std::io::stdin().read_line(&mut input).unwrap(); ... };
```

GOODBYE 후 timeline:
- elapsed 235.5s: GOODBYE 송신
- elapsed 235.5~265.5s: orchestrator가 children kill+wait
- elapsed 265.5s: "sheriff's back" + "What do you do?" print
- elapsed 265.5s+: read_line 시작

우리 코드가 GOODBYE 직후 (elapsed 236s) guess 보내면:
- in_thread 아직 살아있을 수 있음 (child kill 진행 중)
- in_thread가 guess 데이터 읽음 → child_stdin write → broken pipe → drop
- 나중에 read_line은 guess가 없어서 무한 wait → nsjail kill at 300s

## 해결 (검증된 솔루션)

**Guess를 주기적으로 반복 송신** (every 3s) until flag arrives:

```python
end_wait = time.time() + 50
last_send = 0
while time.time() < end_wait and not flag_seen:
    if time.time() - last_send > 3:
        c.send(recovered_secret)  # send (with newline)
        last_send = time.time()
    ln = c.recv(0.5)
    if ln and "flag" in ln.lower():
        flag_seen = True; break
```

**왜 작동하나**: forwarding thread 죽는 시점은 child가 broken pipe 받을 때. 3초마다 반복 송신하면 **적어도 하나는 in_thread death 후 도착** → orchestrator의 stdin buffer에 남음 → read_line이 읽음.

## 시도했다가 실패한 접근

**1. GOODBYE 후 즉시 guess 1번 송신**: forwarder가 consume + drop → 실패.

**2. "What do you do?" prompt 보고 송신**: prompt가 read_line **이후** 출력 가능성. timing 너무 tight (nsjail timeout과 race).

**3. Multiple newlines / large data**: 큰 송신도 forwarder가 한 번에 consume → drop.

## 범용 교훈

orchestrator/wrapper architecture CTF:
1. orchestrator source 확인 → forwarding thread + main thread의 stdin 사용 시점 식별.
2. game phase 종료 → guess phase 사이의 forwarder cleanup window 식별.
3. **반복 송신 (idempotent guess)** 으로 race 우회.
4. orchestrator의 read_line은 newline-terminated → guess 끝에 `\n` 필수.

## 식별 sig
- nsjail wrapped Rust/Go binary
- `connect_to_stdin_stdout` / `pipe_threads` / `forward()` 같은 함수
- nc/socat child process
- game phase + post-game prompt 둘 다 같은 TCP connection 사용

## 참고
- The Black Talon `sources/orchestrator/src/main.rs:30-94`
- 솔버: `bbbctf/the-black-talon/solve/live_v5.py` (last phase)
