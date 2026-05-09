---
name: json-loose-typing-attack-surface
description: json.loads로 받는 입력에서 server가 shape만 검증할 때 type-confusion 공격 surface 체크리스트
type: tool
---

# JSON loose-typing attack surface

## When to use

Server가 `payload = json.loads(...)` 하고 *shape만* (`len(...) == N` 류) 검증한 채 downstream 연산에 그대로 넘기는 경우. CTF에서 매우 흔함.

## Type matrix

`json.loads` 가 만드는 Python type, 그리고 각각의 `str()` 결과:

| JSON literal | Python type | str() | 특기사항 |
|--------------|-------------|-------|----------|
| `123`        | int         | `"123"` | digit 문자열 |
| `"123"`      | str         | `"123"` | **int와 str-동일!** |
| `1.5`        | float       | `"1.5"` | |
| `true` / `false` | bool    | `"True"` / `"False"` | `True == 1`, `False == 0`, `True + 1 == 2` |
| `null`       | NoneType    | `"None"` | |
| `[1, 2]`     | list        | `"[1, 2]"` | comma+space 포함 |
| `{"a":1}`    | dict        | `"{'a': 1}"` | quotes/colon 포함 |
| `"A"`   | str         | `"A"` | unicode |
| `""`         | str         | `""` | 길이 0 ⇒ str-concat에서 dispatcher |

**Python `json` 비표준 확장 (default `loads`):**
- `Infinity`, `-Infinity`, `NaN` 모두 valid → `float('inf')`, `float('nan')`. `str(float('inf')) == 'inf'` (3 chars).
- 큰 int는 그대로 Python big int.

## Attack patterns

### 1. str-collision via type swap

`server_hash = "".join(str(x) for xs in M for x in xs)` 분리자 無:
- A_a의 entry `1234` (int) ↔ A_b의 entry `"1234"` (str) → str() 결과 동일 → hash 동일.
- Free cell 자리에 임의 길이 string 박아 다른 entry 위치/내용 정렬 가능 (Hamiltonicity 2 풀이).

### 2. Boolean sneaking through int checks

- `if x == 1` → `True` 통과
- `nodes[i][1] == nodes[(i+1) % N][0]` → True/False 섞어도 비교 OK
- `pow(g, True, p)` → 정상 동작 (True를 1로 취급)
- `range(False)` → 빈 range. 흐름 제어 우회 가능

### 3. Float sneaking

- `pow(g, 1.5, p)` → TypeError (3-arg pow는 int만)
- `if x > 0` → float OK
- `Infinity` 보내면 float overflow / TypeError로 *서버 크래시* 유도 가능 (helpful 또는 harmful)

### 4. List/dict in unexpected slots

- `str([1, 2, 3]) == "[1, 2, 3]"` → printable structured chars
- 자리 길이 control이 필요한 collision에서 string보다 더 자유 (chars 0-9 외에 `[ , ]` 등)

### 5. Negative indices

- `perm[i] = -1` → `G[-1]` Python wraparound = `G[N-1]`. 인덱스 검증 빠지면 다른 perm으로도 같은 결과 (uniqueness 깨짐).

### 6. Empty containers

- `[]`, `{}`, `""` 길이 0. Loop 0회. assertion `assert x` 실패 가능 (False) — 흐름에 따라 유리/불리.

## Checklist when seeing `json.loads(input(...))`

1. Server의 `check_*` / `validate_*` 함수 모두 읽기. **shape**만 검사? type/value range도 검사?
2. 각 cell이 *내려가는 모든 경로* 추적: type assertion 어디 걸리나? 어디서 처음 산술 연산?
3. 어떤 cell이 type 1 (cycle), type 0 (full-open), 검증 안 됨 등 *역할*을 가지나?
4. *검증 안 되는 cell* 있으면 → 그 자리에 `str`, `[]`, `Infinity`, `True` 등 다 가능. Collision/length-control 재료.
5. 검증되는 cell도 *다른 type으로 같은 결과* 가능한지 보기 (bool↔int, str-of-digits↔int 등).

## 관련
- `attack/hash-strjoin-no-separator-prover-collision` — type swap으로 fm 정렬
- `failures/premature-dlp-wall-missed-value-reuse` — type 자유도가 DLP 우회 가능하게 함
