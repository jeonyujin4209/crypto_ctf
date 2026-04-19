---
name: binary-ilp-pulp-cbc
description: 256 binary 변수 + 128 정수 선형 등식 → pulp+CBC binary ILP 0.2s. LLL embedding이 short vec 못찾을 때 대안. 유일해일 때 Optimal 반환
type: tool
---

# Binary ILP via pulp+CBC for Z-linear Systems with 0/1 Unknowns

## 언제 쓰나

- 변수 `b_j ∈ {0, 1}`, 제약: `Σ A_{i,j} · b_j = c_i` (정수 등식, m개)
- 차원 n (변수 수) ~ 256, m (제약 수) ~ 128, A 계수 small
- LLL embedding 시도했으나 target vec이 basis에 안 올라옴
- 해가 유일하거나 소수 (무작위 A이면 m ≳ n/log₂(max c)로 유일)

## 왜 LLL보다 좋을 때가 있나

LLL/BKZ:
- Lattice rank = n+1, ambient dim n+m+1 → 257 차원 dim 385
- 무작위 binary A라면 target norm ≈ sqrt(n + K²), 하지만 reduced basis는 **target를 basis row로 드러내지 않을 수 있음** (LLL Hermite factor 2^{n/2})
- BKZ block_size 20+ 필요할 수 있고, Sage의 fplll에서 "infinite loop in babai" 크래시도 자주

Binary ILP:
- Branch-and-bound + LP relax → 무작위 유일해 문제에서 node 수 적음
- CBC (free COIN-OR) 256 var / 128 eq ~ 0.2 s
- pip 한 번에 설치: `pip install pulp` (CBC 번들됨)

## 설치 및 기본 호출

```bash
pip install pulp
python -c "import pulp; print(pulp.listSolvers(onlyAvailable=True))"
# 기본: ['PULP_CBC_CMD']
```

## 코드 템플릿

```python
import pulp

def solve_binary_linear(A, c, n_vars):
    """A: list of m rows, each row = list of n bits (0/1). c: list of m ints."""
    prob = pulp.LpProblem("bin", pulp.LpMinimize)
    x = [pulp.LpVariable(f"x{j}", cat='Binary') for j in range(n_vars)]
    prob += 0  # dummy objective (feasibility problem)
    for i, row in enumerate(A):
        idx = [j for j in range(n_vars) if row[j]]  # sparsify
        prob += pulp.lpSum(x[j] for j in idx) == c[i]
    prob.solve(pulp.PULP_CBC_CMD(msg=0))
    status = pulp.LpStatus[prob.status]
    if status != 'Optimal':
        return None, status
    return [int(round(x[j].value())) for j in range(n_vars)], status
```

## 성능 체감 (pulp+CBC)

| n vars | m eqs | density A | time |
|--------|-------|-----------|------|
| 256    | 128   | 50%       | 0.2 s |
| 512    | 256   | 50%       | ~0.85 s (측정) |
| 1024   | 512   | 50%       | ~30 s+ (marginal) |

A가 sparse면 훨씬 빠름. dense 50%에서 n > 1000 넘어가면 CBC marginal.

## 범위 확장

- **범위 제약** (`0 ≤ b_j ≤ M`): `LpVariable(cat='Integer', lowBound=0, upBound=M)`
- **부등식** (`A b ≤ c`): `prob += ... <= c[i]`
- **XOR / 비선형**: ILP로 직접 표현 어려움 → z3 SAT 권장 (→ `z3-bitblast-sat-for-crypto`)

## 적용 가능 vs 불가

**가능**:
- 정수 계수 선형 시스템 + 0/1 (or small bounded) 변수
- 해 유일 또는 few
- n ≲ 512 대략

**불가**:
- 매우 underdetermined (해 기하급수 많음 → LP 완화 non-integral)
- 비선형 (곱, XOR) → z3 / gröbner
- n > 10000 → custom LLL + guessing

## LLL 실패 → ILP 전환 체크리스트

1. Target vec norm이 이론상 짧은가? (yes면 LLL 원칙적 가능)
2. BKZ block_size 20 시도했는가?
3. "infinite loop in babai" 또는 long time → fplll 수치 문제 의심 → ILP로 전환
4. ILP: 위 템플릿 적용, `msg=0`, `status == 'Optimal'` 체크

## 출처

- CryptoHack CTF Archive 2022: FaILProof (SekaiCTF)
  - 128 × 256 binary A, c ∈ [0, 128]^128, 유일한 B ∈ {0,1}^256 복구
  - LLL dim 257×385 basis에 target absent → BKZ crash (fplll babai)
  - pulp+CBC 0.22 s/block × 3 블록 즉시 풀림
- CryptoHack CTF Archive 2022: FaILProof Revenge (SekaiCTF)
  - 256 × 512 binary A, c ∈ [0, 256]^256, 유일한 B ∈ {0,1}^512 복구 (7 블록)
  - pulp+CBC 0.85 s/block, LLL 시도 없이 바로 ILP
- 일반적 tech 배경: SAT/ILP for crypto = Cohn-Heninger style "combinatorial crypto" 해법
