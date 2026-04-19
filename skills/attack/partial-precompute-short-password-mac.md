---
name: partial-precompute-short-password-mac
description: Short (≤40-bit) password in hash-MAC challenge-response (H(pw||label||chal)). Fix chal_c, precompute 1/N subset of pw space, reconnect ~N times until pw in subset. Labels differ so no reflection, but chal_c control enables table attack.
type: attack
---

# Partial Precompute for Short-Password Hash-MAC Challenge-Response

## 전제
Authenticator-style mutual auth:
- Client sends `chal_c` (attacker-chosen).
- Server returns `RS = H(pw || LABEL_S || chal_c)` and fresh `chal_s`.
- Client must reply `RC = H(pw || LABEL_C || chal_s)`.
- pw entropy small (~30-40 bit) but per-session TLE (e.g. 10 s) rules out full online brute.
- `LABEL_S ≠ LABEL_C` (anti-reflection), so RS cannot be replayed as RC.
- Each reconnect draws fresh pw (process restart).

## 왜 안전해 보이나
- 36-bit pw × blake3/sha256 per-call overhead → 수 분 ~ 수 시간의 brute. 10 s 창에서 불가.
- Labels differ → reflection 차단.
- Full precompute: 2^36 × (hash+pw) = 수백 GB ~ TB. 저장 불가.

## 공격 핵심
- `chal_c` is attacker-controlled and can be **fixed** across all sessions.
- With fixed `chal_c`, `RS = H(pw || LABEL_S || chal_c)` is a pure function of pw.
- Precompute `RS` for a **subset** of pw space → constant-time lookup.
- Reconnect until server's pw lands in subset (geometric, expected N).

## 전략
1. **chal_c 고정** (e.g. 16 zero bytes).
2. **pw subset 선택** — 저장/공격 트레이드오프로 결정:
   - First char = specific letter → 1/62 subset (예: 714M 엔트리, ~7 GB, 평균 62 attempts)
   - First 2 chars fixed → 1/3782 subset (~12M 엔트리, ~120 MB, 평균 3782 attempts)
3. Offline precompute:
   - For each pw in subset: `H_prefix[:4] = H(pw || LABEL_S || chal_c)[:4]`
   - Store `(H_prefix, pw)` sorted by H_prefix.
   - Split into chunks if memory tight (by 2nd fixed char, etc.).
4. Online loop:
   - Connect, send fixed chal_c.
   - Receive RS, chal_s.
   - Binary-search `RS[:4]` in chunks; on hash-prefix hit, verify full `H(pw||LABEL_S||chal_c)==RS`.
   - If verified: `RC = H(pw || LABEL_C || chal_s)`, submit → flag.
   - Else close & retry.

## 저장 포맷
- Sorted binary record: `(hash_prefix_4B_LE, pw_bytes)` = (4 + pw_len) bytes.
- 4-byte prefix: false-positive rate ≈ `N_entries / 2^32` per query, verify by full hash (cheap).
- `np.memmap` + `np.searchsorted` → O(log n) lookup, no full-table RAM load.

## 파라미터 가이드
| K (subset 비율 = 1/K) | Table size | Avg attempts | 총 예상 시간 (1 s RTT) |
|---|---|---|---|
| 62 | 1/62 × 2^36 ≈ 7 GB | 62 | ~1 분 |
| 62·61 ≈ 3.8K | 2^36/3.8K ≈ 120 MB | 3.8K | ~1 시간 |
| 62³ ≈ 238K | 1.8 MB | 238K | ~3 일 |

K=62 (첫 문자 fix)가 일반적으로 sweet spot.

## 예: Authenticator (Firebird Internal CTF 2022)
- blake3, 6-char unique alnum pw (62P6 ≈ 2^35.37), 10-s alarm.
- Precompute w/ first_char='a', chal_c=0^16 → 713M 엔트리.
- 12-proc Python blake3 (3 M h/s incl. Python overhead): 237 s precompute.
- 3rd attempt에 hit (geometric mean=62). Flag 확보.

## 왜 작동하나
- `H(pw || LABEL_S || chal_c)`는 fixed-chal일 때 pw → RS 테이블과 등가.
- Preimage 공격 불필요 — 단순 lookup.
- Labels 구분은 **same-session reflection** 방어일 뿐, pw 사이즈 문제엔 무력.
- 각 reconnect의 pw는 독립이므로 배타적 subset으로도 일관된 공격 성공률.

## 적용 불가 케이스
- 서버가 chal_c를 강제로 랜덤화 (e.g. nonce on server side).
- pw가 세션 간 지속 (복수 세션에서 pw 검증 실패가 lockout 유발).
- chal_s가 먼저 와서 chal_c 선택에 영향 (interactive binding).
- pw 엔트로피 > 50 bit (표 자체 구축 infeasible).

## 구현 팁
- pw permutation 순회: `itertools.permutations(remaining_chars, k)` 고속.
- Inner loop: `bytearray` 메시지 버퍼 재활용, 변경 바이트만 업데이트 (2x 빠름).
- Record 저장: `bytearray` 로 bulk write → `np.frombuffer(dtype=[('h','<u4'),('pw','S6')])` 한 번에 변환.
- 병렬화: 두 번째 char로 chunk split → multiprocessing.Pool(n_cores). IPC는 "파일 저장 후 인덱스 반환" 패턴.
- 메모리: chunk별 sort (각 117 MB) → chunks 합치지 말고 lookup 시 chunk마다 searchsorted.
