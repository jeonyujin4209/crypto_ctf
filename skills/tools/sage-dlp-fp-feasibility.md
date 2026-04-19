---
name: sage-dlp-fp-feasibility
description: Sage/PARI 2.17+의 F_p* discrete_log는 index calculus (L_p(1/2))씀. 128비트 prime-order subgroup도 ~50초에 해결
type: skill
---

# Sage `discrete_log` F_p* 실측 타이밍

## 핵심
Sage 10.8 / PARI 2.17.1의 `discrete_log(h, g, ord=q)` 또는 `h.log(g, q)`:
- F_p* (p prime) DLP에 **index calculus** (linear sieve, L_p(1/2)) 사용
- Pollard rho 아님 → prime-order subgroup도 OK

## 실측 (sagemath/sagemath:latest, 8 CPUs, 12GB RAM)

| p bits | subgroup order | time |
|---|---|---|
| 80 | 53-bit prime | 12s |
| 100 | 73-bit prime | 10s |
| 127 | 64-bit prime | 10s |
| **128** | **127-bit prime** | **49.6s** |

## 스케일 예상

L_p(1/2) ≈ exp(sqrt(log p · log log p)):
- 100비트: 수 초~10초
- **128비트: 30초~2분**
- 160비트: 3~10분
- 192비트: 30분~2시간
- 256비트: 수 시간~하루 (CADO-NFS 고려)

## 호출 패턴 (Python에서 docker로)

```python
def sage_dlp(p, g, h, q):
    import subprocess, os, textwrap
    script = textwrap.dedent(f"""
        F = GF({p})
        print(F({h}).log(F({g}), {q}))
    """)
    workdir = os.path.dirname(os.path.abspath(__file__))
    with open(f"{workdir}/_dlp.sage", "w") as f:
        f.write(script)
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    mount = workdir.replace("/", "\\")
    out = subprocess.check_output(
        ["docker", "run", "--rm", "-v", f"{mount}:/work",
         "sagemath/sagemath:latest", "sage", "/work/_dlp.sage"],
        env=env, timeout=600)
    return int(out.decode().strip().splitlines()[-1])
```

## Windows Docker Desktop 함정

- **WSL2에 CPU 0개 할당되면 sage가 영원히 멈춤** (100% CPU / 0 available 상태)
- 해결: `C:\Users\<user>\.wslconfig`:
  ```
  [wsl2]
  processors=8
  memory=12GB
  ```
- `wsl --shutdown` 후 Docker Desktop 재시작

## Docker 실행 세부사항

- **`sage file.sage`** 직접 호출. `bash -c "sage file.sage > out.txt"` 래퍼 쓰면 sage가 interactive mode로 진입함
- Windows path: `-v 'd:\path:/work'` (backslash, single quotes) + `MSYS_NO_PATHCONV=1`
- `docker run -d --name NAME ...` + `docker logs -f NAME` 으로 스트리밍

## 관련
- `attack/gaussian-int-padic-dlp` — 128-bit F_p DLP로 k mod q 복구
- `failures/premature-dlp-infeasibility` — Pollard rho로 오판 금지
