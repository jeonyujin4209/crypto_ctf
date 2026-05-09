---
name: sage-docker-custom-image-pycryptodome
description: sagemath/sagemath docker 이미지에 pycryptodome/pwntools 등 빠진 모듈을 한 줄 Dockerfile로 layer 추가
type: tool
---

# Sage docker custom image with crypto libs

## 문제

`sagemath/sagemath:latest` 도커 이미지에 `Crypto.Cipher.AES`, `pwn`, 기타 일반 CTF 라이브러리 없음:

```
docker run --rm sagemath/sagemath:latest sage -c "from Crypto.Cipher import AES"
ModuleNotFoundError: No module named 'Crypto'
```

`--rm`이라 매번 사라지므로 매 호출마다 `sage --pip install ...` 하면 ~30초 낭비.

## 해결

1줄 Dockerfile로 layer 추가:

```dockerfile
FROM sagemath/sagemath:latest
RUN sage --pip install pycryptodome pwntools
```

```bash
docker build -t sage-crypto -f Dockerfile.sage .
```

이후 `sage-crypto:latest` 이미지 사용. layer cache 덕분에 빌드 한 번 + 이후 즉시.

## Python wrapper (Windows path 처리)

`tools/docker-windows-path-mount` 와 함께 사용:

```python
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
wd = HERE.replace('\\', '/')
mount_host = f'/{wd[0].lower()}{wd[2:]}'  # D:/foo → /d/foo
env = os.environ.copy(); env['MSYS_NO_PATHCONV'] = '1'
cmd = ['docker', 'run', '--rm',
       '-v', f'{mount_host}:/work', '-w', '/work',
       'sage-crypto:latest', 'sage', sys.argv[1]]
subprocess.run(cmd, env=env)
```

## 사용 사례

- ECDH oracle 공격에서 Sage로 EC 점 연산 + AES로 oracle response 검증
- LWE/SIDH challenge에서 Sage 격자 + 해시 검증 함께
- pwntools가 필요한 listener 기반 challenge 통째로 sage script 안에서 처리

## 관련
- `tools/docker-windows-path-mount` — Windows에서 `-v` 마운트 path 처리
- `attack/invalid-curve-attack-alternative-b` — Sage EC + AES oracle 결합 사용 예
