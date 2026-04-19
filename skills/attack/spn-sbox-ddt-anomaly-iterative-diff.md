---
name: spn-sbox-ddt-anomaly-iterative-diff
description: Custom SPN cipher에서 S-box DDT 이상치(1 entry >> random baseline) + parity-preserving permutation이 만나면 iterative differential trail로 per-byte key 복구 가능. 전 round key peeling으로 master key까지 도달.
type: attack
---

# SPN with Anomalous S-box DDT + Parity-Preserving Permutation = Iterative Diff

## 시나리오

CTF custom block cipher:
- SPN 구조 (sub → K_r XOR → per 반복).
- 8-bit S-box 제공 (look-up table).
- Permutation이 nibble 단위 (P_box + P_nib).
- Key schedule: `K0 = master K`, `K_i = sha512(K)[...]`.
- Encrypt/Decrypt oracle, limited query budget.

## 취약점 탐지 체크리스트

### Step 1: S-box DDT scan
```python
DDT = [[0]*256 for _ in range(256)]
for x in range(256):
    for dx in range(256):
        DDT[dx][S_box[x] ^ S_box[x^dx]] += 1

top = max(DDT[dx][dy] for dx in range(1,256) for dy in range(256))
```
- Random 8-bit S-box의 max DDT entry: 6~16.
- **Max > 50이면 의심, > 100이면 trapdoor 확정.**
- 특정 (dx, dy) → 확률 DDT[dx][dy]/256로 유지되는 single-round differential.

### Step 2: Permutation parity check
```python
# P_nib가 bit permutation (linear)인지 확인: P_nib[P_nib[v]] == v (involution)?
# P_box가 nibble parity 보존: P_box[even] → even values, P_box[odd] → odd values?
even_preserve = all(P_box[i] % 2 == 0 for i in range(0, 32, 2))
odd_preserve = all(P_box[i] % 2 == 1 for i in range(1, 32, 2))
```
- **parity 보존이면**: 모든 byte에 같은 diff D를 두면 per 후에도 규칙적 patten 유지.
  - `per(all D) = all D'` where D' = P_nib 적용된 D.

### Step 3: Iterative trail
- DDT anomaly entry `(dx, dy)`와 P_nib가 dx ↔ dy swap하면:
  - `pt diff = dx × 16` → sub (prob) → `dy × 16` → K XOR (no change) → per (det) → `dx × 16` → ...
  - **2-round iterative**: `dx` → `dx` (via `dy`).

## 공격 알고리즘

### Phase 1: Data collection
```python
DIFF = bytes([dx]*16)  # iterative diff value
N = budget // 2  # pairs
pairs = []
for _ in range(N):
    pt1 = random_bytes(16)
    pt2 = pt1 XOR DIFF
    ct1 = encrypt(pt1); ct2 = encrypt(pt2)
    pairs.append((pt1, pt2, ct1, ct2))
```

### Phase 2: Per-byte K_last recovery (differential key recovery)
Each output byte has a **small past cone** of active S-boxes. Per-byte trail probability ≈ (DDT_max/256)^cone_size ~ 0.01-0.1.

```python
for i in range(16):
    counts = [0]*256
    for K_guess in range(256):
        for pt1, pt2, ct1, ct2 in pairs:
            y_prev_1 = S_box_inv[ct1[i] ^ K_guess]
            y_prev_2 = S_box_inv[ct2[i] ^ K_guess]
            if (y_prev_1 ^ y_prev_2) == dx:  # expected diff at pre-last-sub state
                counts[K_guess] += 1
    K_last[i] = argmax(counts)
```

- **Signal**: correct K gives count ≈ N × prob_per_trail.
- **Noise**: wrong K gives count ≈ N / 256.
- **Distinguishable** if past cone size ≤ ~12 (for DDT = 172/256, N ~ 1500).

### Phase 3: Round peeling
1. `K_last` 복구 → `y_{prev}[i] = sub_inv(ct[i] XOR K_last[i])`.
2. `per_inv(y_prev)` 계산 (K_next XOR된 상태).
3. 다시 per-byte attack으로 `K_next` 복구.
4. 반복: K3 → K2 → K1.

### Phase 4: K0 (master K) direct recovery
Cipher structure가 `sub(pt) → K0 XOR → per → ...` 이면:
- `y1 = per(sub(pt) XOR K0)` → `per_inv(y1) = sub(pt) XOR K0`.
- **K0 = per_inv(y1) XOR S_box(pt)** — 어떤 pair 하나로도 직접 계산.

### Phase 5: Robustness — top-N + single-byte swap retry
Top-1 candidate가 가끔 noise에 밀려 틀림 (1500 pairs로 ~25% trials에서). 해결:
1. Phase 2에서 **top-5 candidates per byte** 저장.
2. Top-1 조합으로 전 phase 돌려 K0 복구 → 1 known (pt, ct)로 검증.
3. 실패 시: 각 byte를 top-2, 3, 4, 5로 하나씩 swap해서 16×4=64개 시도 → 거의 항상 성공.
4. 여전히 실패 시: 2-byte swap combinations.

## 복잡도

- Data: `2 × N` encrypts (N ≈ 1500 for DDT 172/256, 3-round cipher, 16-byte state).
- Compute: Phase 2 각 byte 256 × N = ~400K ops → 16 bytes → ~6M per phase × 4 phases + retries.
- 수 분 내 완료 (Python).

## 핵심 원칙

- **Random S-box 가정 금지**: CTF custom cipher는 trapdoor 심어놓을 수 있음. DDT/LAT scan 먼저.
- **Permutation linearity 관찰**: P_nib이 bit permutation이면 GF(2) linear → diff 전파가 clean.
- **Per-byte cone 분석**: full-state trail probability가 낮아도, 각 output byte는 past cone만 영향 받아서 attack이 tractable.
- **검증 pair로 verify**: partial K 복구 후 항상 1개 known (pt, ct)로 verify 후 submit.

## 출처

- CryptoHack CTF Archive 2022: Key recovery (DCTF).
- `S_box`에 `DDT[0xbe][0xeb] = 172` (random max 16).
- `P_box` parity-preserving + `P_nib` swap `0xb ↔ 0xe` → iterative trail.
- 1500 pairs (3000 blocks, 정확히 budget 한계)로 K0..K3 모두 복구.
- Flag: `dctf{M4k1ng_Sb0x3s_1s_t00_h4rd}` — 의도된 취약점 confirmation.
