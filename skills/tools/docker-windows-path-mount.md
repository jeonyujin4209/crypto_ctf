---
name: docker-windows-path-mount
description: Windows git-bash에서 `docker run -v` 자동 POSIX 변환이 subprocess.run 호출에서는 안 됨. 수동 변환 + MSYS_NO_PATHCONV=1 필요.
type: tool
---

# Docker Volume Mount from Python on Windows

## 문제
Windows git-bash / MSYS2 shell 직접 실행:
```bash
docker run -v "D:/work:/work" ...   # OK (shell이 자동 변환)
docker run -v "/d/work:/work" ...   # OK
```

Python에서 subprocess 호출:
```python
subprocess.run(['docker', 'run', '-v', 'D:/work:/work', ...])
# Error: 'D:/work:/work' is not a valid path
# or: 'C:/Program Files/Git/work' is invalid  (git-bash POSIX magic 역변환)
```

원인: Python subprocess는 shell을 거치지 않음 → MSYS2 자동 path 변환 안 됨. 게다가 Docker Desktop은 argument를 받는 Git Bash 래퍼가 있을 수 있어서 `/d/...`를 오히려 `C:/Program Files/Git/d/...` 로 바꿔버림.

## 해결

### 1) 변환 로직
```python
import os
HERE = os.path.dirname(os.path.abspath(__file__))  # 'D:\\path\\to\\dir'
wd = HERE.replace('\\', '/')                       # 'D:/path/to/dir'
assert wd[1] == ':'
mount_host = f'/{wd[0].lower()}{wd[2:]}'           # '/d/path/to/dir'
```

### 2) MSYS_NO_PATHCONV=1 환경변수
```python
env = os.environ.copy()
env['MSYS_NO_PATHCONV'] = '1'   # git-bash 자동 변환 억제
cmd = ['docker', 'run', '--rm',
       '-v', f'{mount_host}:/work',
       '-w', '/work',
       'sagemath/sagemath:latest', 'sage', 'script.sage']
subprocess.run(cmd, env=env, ...)
```

### 3) 공백 있는 경로
`cmd` array로 넘기면 shell 인용 문제 없음. 단 Docker 자체가 `-v` value에 공백 있으면 처리 못 할 때가 있음 → 작업 디렉토리를 공백 없는 곳으로 복사하거나 symlink 필요할 수 있음. (경험상 docker desktop 최신버전은 공백 OK).

## 체크리스트
- `-v` 값: `/{drive_lower}{path}:/container_path`
- `env['MSYS_NO_PATHCONV'] = '1'`
- `subprocess.run(cmd_list, ...)` (shell=False, list 형태)
- CWD는 native Windows path로 (argv만 POSIX 변환)

## 출처
- C0ll1d3r (Firebird Internal CTF 2022): sage docker LLL pipeline 중 `D:\...` 직접 넘기니 `C:/Program Files/Git/work` 엉뚱 에러. `/d/...` 변환 + `MSYS_NO_PATHCONV=1`로 해결.
- 이전 Authenticator (Firebird Internal CTF 2022) precompute 작업 등 Windows docker 관련 작업 일반.
