---
name: sage-script-exit-returncode
description: .sage 스크립트에서 sys.exit(N)은 preparser 간섭으로 subprocess returncode가 틀어짐 (0 요청했는데 1 나오고 stdout 끝에 "0" 출력되기도). raise SystemExit(N) 쓰고, 통신은 stdout 마커로.
type: tool
---

# Sage Script Exit / Return-Code Quirks

## 문제
Python에서 sage docker(또는 `sage script.sage`)를 subprocess로 돌리면:
- `sys.exit(0)` 호출했는데 `proc.returncode == 1` 로 나옴
- stdout 마지막 라인에 `0` (숫자) 단독 출력
- `sys.exit(1)` → returncode `1` (이건 맞음)

원인: sage `.sage` 파일은 preparser가 Python 코드 변환. Integer literal을 `Integer(...)`로 감싸고, exit flow에 개입해서 `sys.exit` 인자가 이상하게 전달됨. Sage REPL에서 expression의 value를 print 하는 동작이 script 모드에도 leak되는 걸로 보임.

## 해결

### 1) Exit은 `raise SystemExit(N)`
```python
# .sage 파일
if found:
    print(f'RESULT: {answer}')
    raise SystemExit(0)  # sys.exit(0) 금지

print('no result')
raise SystemExit(1)
```

`raise`는 preparser가 건드리지 않음 → 깔끔하게 exit.

### 2) stdout 마커로 통신 (returncode 의존 금지)
```python
# 호출측 (Python)
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=...)
# returncode는 참고만 — 주 판단은 stdout 파싱
for line in proc.stdout.splitlines():
    if line.startswith('RESULT: '):
        return line[len('RESULT: '):].strip()
# 못 찾으면 실패
raise SystemExit('no RESULT line from sage')
```

패턴: 성공 시 `RESULT: <payload>` 한 줄, 실패 시 `NO RESULT` 같은 마커 + `raise SystemExit(1)`. 호출측은 마커 grep만 함.

## 왜 이게 낫나
- returncode 꼬임 debug 시간 0
- 디버그 출력 자유롭게 섞여도 `RESULT:` prefix만 지키면 됨
- sage 버전업 되어도 preparser 변화에 robust

## 출처
- C0ll1d3r (Firebird Internal CTF 2022): sage LLL 스크립트가 해답 찾고 `sys.exit(0)` 했는데 returncode=1 + stdout 끝에 `0` 출력. `raise SystemExit(0)`로 바꾸고 RESULT: 라인 grep 방식으로 호출측 단순화.
