---
name: sigma-protocol-batch-fs-attack-checklist
description: Sigma protocol / Fiat-Shamir NIZK 만났을 때 first-pass 점검 순서. Online vs batch, 직렬화 방식, cell 검증 비대칭이 attack surface
type: tool
---

# Sigma protocol / Fiat-Shamir NIZK — first-pass attack checklist

## When to use

ZK challenge 류, 특히:
- "prove you know witness w for statement S" (Hamiltonicity, graph 3-coloring, RSA-knowledge, Schnorr, …)
- N-round commit-challenge-response
- Server가 `hash(...)` 로 challenge bits 뽑음 (Fiat-Shamir)

## Step 1. Online vs batch FS

가장 먼저 결정.

```python
# Online (per-round) — grindable
for i in range(N):
    A_i = recv()
    state = hash(A_i, state)
    challenge_i = state[-1] & 1
    z_i = recv()
    verify(A_i, challenge_i, z_i)

# Batch — non-grindable directly
for i in range(N):
    A_i = recv()
for i in range(N):
    z_i = recv()  # 또는 함께
state = b''
for i in range(N):
    state = hash(A_i, state)
challenges = bits(state)
for i in range(N): verify(A_i, challenges[i], z_i)
```

- **Online**: A 보내고 challenge 받기 *전*에 다음 A 못 만듦. ⇒ A_i 무한 재시도해서 challenge=0 (또는 prover에게 유리한 비트) 강제 가능. ~50% 성공률, 라운드당 평균 2회 시도. → `attack/hamiltonicity-online-fs-grinding`.
- **Batch**: 모든 A 모은 후 challenge 결정. Per-round grinding 안 됨. ⇒ **다른 trick 필요**.

## Step 2. Hash 직렬화 검사

Batch FS면 hash input의 *직렬화 방식*이 거의 항상 약점:

```python
# 위험한 패턴
"".join(str(x) for x in messages)          # 분리자 無
str(M).encode()                            # python repr — 짧은 entries 분간 어려움
b''.join([m.to_bytes(L) for m in messages]) # L이 충분히 큰지? variable-length 위험
json.dumps(messages, sort_keys=False)      # ordering 의존
```

**체크**:
- 분리자가 byte-unambiguous한가? (`,` 만으로는 부족 — `[1, 2, 3]` vs `[1, 23]` collision 가능)
- 각 entry가 *고정 길이*인가? variable-length면 두 입력이 같은 byte stream 만들 가능성.
- type-tag 있는가? (str/int/list 구별 byte)
- nested structure는 어떻게 직렬화? flatten되면 grouping 정보 잃음.

직렬화에 ambiguity 있으면 → **두 다른 메시지 컬렉션이 같은 hash** ⇒ batch FS 깨짐. `attack/hash-strjoin-no-separator-prover-collision` 참고.

## Step 3. Challenge bit 처리 quirks

```python
challenge_bits = bin(int.from_bytes(state, 'big'))[-N:]
```

- `bin(N)` 은 `'0b...'` 시작. `[-N:]` 슬라이싱이 prefix 포함하면 'b' 문자 → `int(c)` 크래시.
- 작은 확률이지만 발생 시 attacker가 server crash → flag 못 받음 (해로움). state high-bit 강제 1 가능?

```python
challenge_bits = state[i:i+N//8]  # raw bytes
```

- 더 안전. 그러나 여기서도 endianness/slice index 실수 가능.

## Step 4. Verify branches 비대칭

Sigma protocol은 challenge-bit별로 다른 verify 경로:

```python
if challenge == 0:
    open_all()   # 25 cells 다 검증 (all-integer)
else:
    open_subset()  # 5 cells만 검증 (subset만 integer 강제)
```

→ challenge=1 경로의 *비검증 cell*이 자유 surface. 거기에 임의 JSON 박을 수 있음 (`tools/json-loose-typing-attack-surface`).

→ A를 두 종류로 prepare: A_a (challenge=0용 valid), A_b (challenge=1용 valid). 같은 first_message 만들 수 있으면 → 양쪽 다 동시에 만족하는 hash 결정. challenge bit 미리 보고 round별 적절한 A 송신.

## Step 5. Witness-shape requirement 우회

challenge=1 경로가 요구하는 witness 구조 분석:
- Hamiltonian cycle: cycle = N edges, all distinct, chain. 원래 그래프 G에서 HC 없을 때, fake A에서 HC를 *강제로* 만드는 게 가능한지?
- 5-coloring: 인접 쌍이 다른 색.
- 3-SAT: clause 만족.

Server가 cycle/coloring/clause 자체는 *우리가 보낸 A의 cells*만 검사. 원래 G와 cross-check 안 하면 → 우리 A를 fake HC matrix로 만들 수 있음. 이게 가능하면 batch FS collision attack 의 한쪽 (A_b) 구성 가능.

## Step 6. Replay / parameter binding

`hash_committed_graph(A, state, comm_params)` 처럼 comm_params 들어가면 같은 server 재시작 후에도 같은 prefix. 다른 session/round의 hash 재활용 시도 가능?

## Quick decision tree

```
Sigma + FS challenge 보임
├─ Online FS? → grinding (Step 1 link)
├─ Batch FS:
│  ├─ Hash 직렬화 ambiguous? → message collision (Step 2)
│  ├─ Verify 경로 비대칭 + 자유 cell 있음? → dual-prepare A_a/A_b (Step 4)
│  ├─ Challenge bits 처리에 edge case? → 강제 트리거 (Step 3)
│  └─ Witness shape forge 가능? → fake-HC A_b (Step 5)
└─ 둘 다 아닌 hybrid? → 라운드별 다르게 attack 조합
```

## 관련
- `attack/hamiltonicity-online-fs-grinding` — Step 1 online 케이스
- `attack/hash-strjoin-no-separator-prover-collision` — Step 2/4 batch 케이스 풀이
- `tools/json-loose-typing-attack-surface` — Step 4의 자유 cell 활용
- `failures/premature-dlp-wall-missed-value-reuse` — Step 4 collision 만들 때 DLP 결론 함정
