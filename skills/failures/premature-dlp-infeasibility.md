---
name: premature-dlp-infeasibility
description: F_p* DLP 크기 견적을 Pollard rho로만 계산해 "infeasible" 판정 금지. PARI는 index calculus, 128비트 prime order도 1분
type: failure
---

# F_p* DLP 불가능 성급 판정

## 실패 패턴
Challenge: 128-bit p, 127-bit prime q = (p-1)/2. g order q, F_p* 내부 DLP 필요.

내가 했던 잘못된 추론:
> Pollard rho: sqrt(q) ≈ 2⁶³·⁵ ops → 10¹⁹ 연산 → 수 백 년. 불가능.

→ Sage 안 돌려보고 CADO-NFS 필요하다고 결론. 3분 기다리다가 포기.

## 실제
- PARI 2.17.1의 `znlog` (Sage `discrete_log` 백엔드)는 F_p^\* 에 대해 **index calculus** (linear sieve, L_p(1/2)) 사용
- 128-bit p + 127-bit prime subgroup = **49.6초** (sagemath docker, 8 CPUs)
- 수학적 복잡도 ≠ 실제 구현 복잡도

## 교훈
1. **DLP 크기 계산을 Pollard rho로만 하지 말것**. PARI/FLINT/CADO 등이 어떤 알고리즘 쓰는지 모르면 **실제 돌려봐야** 앎
2. **실측 벤치마크 먼저**. 80비트 DLP 몇 초인지부터 재면 scaling 감 잡힘
3. **Docker environment issue vs algorithm issue 구분**. 내 첫 시도는 WSL2에 CPU 0개 할당돼서 멈춘 거였는데, 이걸 "DLP infeasible" 증거로 오해
4. **timeout 1시간 넉넉히** 걸고 백그라운드로 돌려두기

## 벤치마크 템플릿

```python
# sage script
import time
for bits in [80, 100, 120, 127]:
    p = next_prime(2^bits)
    F = GF(p)
    g = F.multiplicative_generator()
    order = p - 1
    max_factor = max(f for (f, _) in factor(order))
    h = g^(order // max_factor)   # order = max_factor
    k = 12345 % max_factor
    target = h^k
    t0 = time.time()
    r = discrete_log(target, h, ord=max_factor)
    print(f"bits={bits}, max_factor={max_factor.nbits()}b, time={time.time()-t0:.1f}s")
```

80비트부터 시작해서 scaling 보고 128비트가 가능한지 판단.

## 관련
- `tools/sage-dlp-fp-feasibility` — 실측 타이밍표
- `attack/gaussian-int-padic-dlp` — 이 문제 풀이
- `tools/stuck-checklist-5-questions` — "복잡해 보여서 skip" 전 확인할 5문
