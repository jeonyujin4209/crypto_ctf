---
name: mmh3-seed-independent-differential-collision
description: MurmurHash3_x86_32 multi-seed collision via 2-block top-bit differential. Bloom filter / multi-hash DB add+check 우회.
type: attack
---

# MurmurHash3_x86_32 — seed-independent differential collision

`mmh3.hash`(_x86_32) body: `T(h, k') = ROTL(h ^ k', 13) * 5 + c`,
`process(k) = ROTL(k * c1, 15) * c2`(`c1=0xCC9E2D51, c2=0x1B873593`, both odd → bijective in `k`).

목표: **모든 seed에 대해** `mmh3(K1, s) == mmh3(K2, s)` 인 두 키 쌍. 길이만 같으면 seed 자체가 collision trail에 영향 안 줌 (seed는 초기 `h`만 결정).

## 2-block (8-byte) collision trail

| step | property |
|---|---|
| 입력 state diff `Δh = 0x00040000` (bit 18) | `ROTL(Δh, 13) = 0x80000000` |
| 그 후 `*5 + c` | top-bit-only XOR diff 정확히 보존: `5·2³¹ mod 2³² = 2³¹`. lower 31bit가 동일하므로 캐리 흐름도 동일 → diff = `0x80000000` 유지 |
| 두 번째 block의 processed value diff `0x80000000` 제공 | `h_a ^ a2_p == h_b ^ b2_p` → state EQUAL |
| 이후 공통 suffix | 같은 state에서 같은 입력으로 진행 → 동일 final hash |

**즉**:
- Block 1 raw 바이트 `a1, b1` 선택 시 `process(a1) ^ process(b1) = 0x00040000`
- Block 2 raw 바이트 `a2, b2` 선택 시 `process(a2) ^ process(b2) = 0x80000000`
- `K1 = a1‖a2`, `K2 = b1‖b2` (8 bytes 각). 공통 suffix 붙이면 `mmh3(K1‖S, s) == mmh3(K2‖S, s)` for all `s`.

## 구현

```python
C1, C2, MASK = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
INV_C1 = pow(C1, -1, 1<<32)
INV_C2 = pow(C2, -1, 1<<32)
def proc(k):
    k = (k*C1)&MASK; k = ((k<<15)|(k>>17))&MASK; return (k*C2)&MASK
def inv_proc(p):
    p = (p*INV_C2)&MASK; p = ((p>>15)|(p<<17))&MASK; return (p*INV_C1)&MASK

# 임의 p1, p3 → 쌍 만들기
p1 = randbits(32); a1 = inv_proc(p1); b1 = inv_proc(p1 ^ 0x00040000)
p3 = randbits(32); a2 = inv_proc(p3); b2 = inv_proc(p3 ^ 0x80000000)
K1 = a1.to_bytes(4,'little') + a2.to_bytes(4,'little')
K2 = b1.to_bytes(4,'little') + b2.to_bytes(4,'little')
# verify: all(mmh3.hash(K1,s)==mmh3.hash(K2,s) for s in range(N))
```

확률 1로 작동 (carry exception 없음 — top-bit-only diff에서 `5·diff` 가 정확히 `0x80000000`).

## 어디에 쓰나

- **Bloom filter add+check 우회 (SekaiCTF 2022 diffecient)**: `add_sample(K1)` → `check_admin(K2)` 통과. `K1 != K2`라 added_keys check 통과, 둘의 mmh3 hash가 모든 seed에 대해 같으니 47개 bucket 다 set.
- **Hash table 충돌 (HashDoS)**: 같은 hash 가지는 키 무한 생성. `K1‖K2‖suffix`도 collision pair (chaining 가능).
- **Multi-hash MAC/fingerprint 회피**: 하나의 키 등록 후 다른 바이트열로 같은 fingerprint 흉내.

## Caveats

- **MurmurHash3_x86_32 한정**. mmh3_x64_128, mmh3_x86_128 다른 trail 필요.
- **Block 단위 (4 byte) little-endian**. bytes는 `(...).to_bytes(4, 'little')`.
- **format regex 통과 필요**: 32+ bytes, lower/upper/digit/special. K1, K2의 8byte 앞부분이 ASCII 안 될 수 있으니 suffix 32B에 모든 char class 포함 (`b"abcDEFG1!" + ...`).
- **suffix에 `\n` 금지** — `re.match(b".{32,}", key)` 가 죽음 (`.`는 newline 매치 안 함).
- 더 긴 collision suffix가 필요하면 위 trail을 한 번 더 chain (16 bytes per pair). `2^n` collision → `16n` bytes.
