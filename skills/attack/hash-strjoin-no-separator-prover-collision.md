---
name: hash-strjoin-no-separator-prover-collision
description: 분리자 없는 str-join 해시는 다른 입력 컬렉션이 같은 해시를 만들 수 있어 Fiat-Shamir 안전성을 깨뜨림
type: skill
---

# Hash with separator-less str-join → prover-controlled collision

## When to use

- Fiat-Shamir의 challenge가 `hash("".join(str(x) for x in messages))` 같은 식으로 계산됨
- "Output should be unique but isn't" 류 힌트
- Batch FS (모든 A 모은 뒤 챌린지 계산) — 라운드별 grinding 불가
- Prover가 메시지 리스트의 일부 원소 *타입과 길이*를 자유롭게 고를 수 있음 (JSON 입력 등)

## The vulnerability

해시 입력이 `"".join([str(x) for xs in G for x in xs])` 식으로 만들어지면, *다른 매트릭스*가 같은 flat 문자열을 만들 수 있음. 분리자/길이 prefix가 없기 때문.

예: `[12, 34]`와 `[1, 234]` → 둘 다 `"1234"`. SHA256 입력 동일 → challenge 동일.

## Application: Hamiltonicity 2 (CryptoHack 2024)

문제 구조:
- 그래프 G는 HC 없음 (3-cycle + 2-cycle 분리)
- 128 라운드 batch FS sigma protocol
- 각 라운드: prover가 A (commit matrix) 보냄 → 모든 라운드 후 hash chain → challenge bits
- challenge=0: A는 perm(G)에 open되어야 함 → 25 cells 모두 valid Pedersen commit
- challenge=1: A의 cycle 5 cells가 commit-to-1, 나머지 20 cells는 검증 안 됨 (어떤 JSON 값이든 OK)

핵심 insight: **A_a (type 0용) 와 A_b (type 1용) 가 같은 first_message 만들면 hash 동일** → challenge bits 사전 계산 가능, round별로 적절한 A 선택해 보냄.

### 정렬 트릭 (DLP 우회)

A_b의 5 cycle commit 값을 A_a의 5 commit-to-1 값과 *동일하게* 두고, A_b 안에서 그 cell들이 *문자 오프셋* 측면에서 A_a의 commit-to-1 위치와 정확히 정렬되도록 free cell 길이 조정.

- A_a: honest commit_to_graph(G). 1-positions S_a.
- A_b: cycle positions S_b ⊂ {0..24} (HC edge 위치). σ: S_b → S_a (bijection).
  - Cycle cell at flat p = A_a[σ(p)] (정수, commit-to-1, 같은 r 사용)
  - Free cell at flat r = JSON 문자열, 길이 L_r 선택, 내용 = fm_a의 해당 substring

각 그룹 (cycle cell 사이 free cells) 의 슬랙:
```
slack_g = offset_a(σ(p_g)) - (already-consumed offset)
```
모든 슬랙이 ≥ 0이고 그룹 내 free cell ≥ 1이면 feasible (마지막 free cell에 모두 부여).

### Cycle 선택 조건
S_b의 *최소 gap ≥ 2* 여야 함 (인접한 cycle position은 슬랙=0 강제, 보통 위배). 예: cycle 0→1→3→2→4→0 → S_b = {1, 8, 14, 17, 20}.

### Z payload
- type 1: `z = [cycle_edges, [r1..r5]]` — cycle openings는 A_a의 1-position들의 r 값.
- type 0: `z = [identity_perm, openings_a]` — 25 cells 전체.

## Why it works

- A_b의 free cells가 JSON 문자열이라 `str(x) == x` (인용부호 없음) → 임의 길이/내용 가능
- A_a의 1-position cells = 자체적으로 commit-to-1 → A_b의 cycle cells에 그대로 복사 → DLP 불필요
- offset 정렬: `offset_b(p) = offset_a(σ(p))` 만 만족하면 같은 chars 같은 위치 → fm_a == fm_b

## Pitfalls

- `bin(int.from_bytes(state, 'big'))[-128:]` 가 'b' 포함하면 int() 크래시 — bit_length < 128일 확률 ≈ 2^-129, 무시 가능
- Cycle 노드 순서 → 체인 조건 `nodes[i][1] == nodes[(i+1)%N][0]`
- Cycle gap = 1인 cycle 선택하면 슬랙 = 0 강제로 σ 매칭 불가 — gap ≥ 2 cycle 골라야

## Challenges
- CryptoHack Hamiltonicity 2 — `crypto{ambiguous_hashing_encoding_ruins_RO_reduction}`
