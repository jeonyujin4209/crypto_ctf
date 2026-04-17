---
name: sha256-length-extension-via-oracle
description: Hash oracle에서 제어 가능한 입력으로 SHA256 padding을 재현 → hash output을 intermediate state로 사용해 length extension
type: skill
---

## 상황

SHA256(permute(secret + controlled_bytes)) 형태의 hash oracle이 있고:
1. **입력 길이를 늘릴 수 있음** (예: pbox 길이 검증 부재, 반복 인덱스 허용)
2. **일부 바이트를 직접 제어** 가능 (salt, nonce 등)
3. Secret 자체는 모르지만 oracle 호출 횟수 제한 내에서 복구해야 함

## 핵심 아이디어

SHA256은 Merkle-Damgård 구조. `H(M)` = 마지막 블록 처리 후의 internal state.

→ 제어 가능한 바이트로 **SHA256 내부 패딩(0x80 + zeros + 8-byte length)을 메시지 안에 재현**하면, 한 블록짜리 해시의 output이 곧 멀티블록 메시지의 intermediate state가 된다.

```
H(msg_21bytes) ← 1블록: [msg(21)] [0x80] [zeros(34)] [length_8bytes]

Extended msg:   [msg(21)] [0x80] [zeros(41)] [0xA8] | [extra_bytes...]
                 ↑ block 1 = padded(msg) 와 동일 ↑    ↑ block 2 ↑

→ intermediate_state_after_block1 = H(msg_21bytes)
→ H(extended_msg) = compress(H(msg_21bytes), padded(block2))
```

## 공격 절차

### Phase 1: h_targets 수집
Oracle에 정상 입력 → `H(secret + known + random_byte)` 수집. 각 해시는 잠재적 intermediate state.

### Phase 2: h_lookups 수집 (padding 임베딩)
입력을 확장하되, 제어 바이트로 SHA256 패딩을 재현:
- `0x80` = padding start marker
- `0x00` * N = zero padding
- length bytes = 원본 메시지 길이 × 8 (big-endian)

Block 1이 Phase 1의 padded input과 동일하도록 구성.

### Phase 3: Pepper 매칭 (offline)
각 h_target을 intermediate state로 사용 → block 2를 처리 → h_lookup과 매칭.

```python
from hash import SHA256  # custom: intermediate state에서 초기화

for h in h_targets:
    for candidate in range(256):
        s = SHA256(h)
        s.feed(bytes([candidate]) + sha256_padding_for_total_length)
        if s.digest() in h_lookups:
            return candidate, h
```

### Phase 4: Mapper 구축 + Secret 복구
매칭된 h_target으로 `{H(char, pepper) : char}` mapper 생성.
Oracle에서 secret byte를 block 2에 배치 → mapper lookup으로 한 글자씩 복구.

## Custom SHA256 (intermediate state 초기화)

```python
import struct

K = [0x428a2f98, 0x71374491, ...]  # SHA256 round constants (64개)
MASK = 0xffffffff

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK

def compress(state, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & MASK)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & MASK & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & MASK
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d+temp1)&MASK, c, b, a, (temp1+temp2)&MASK
    return tuple((s+x)&MASK for s, x in zip(state, (a,b,c,d,e,f,g,h)))

class SHA256:
    def __init__(self, digest_bytes):
        self.state = struct.unpack('>8I', digest_bytes)
    def feed(self, block):
        assert len(block) == 64
        self.state = compress(self.state, block)
    def digest(self):
        return struct.pack('>8I', *self.state)
```

## SHA256 패딩 규칙 (quick ref)

메시지 길이 L bytes → 패딩:
- `0x80` (1 byte)
- `0x00` × (55 - L % 64) bytes (L < 56인 경우)
- 8-byte big-endian length: `L * 8`
- 총 패딩 = 64 - L % 64 bytes (L % 64 < 56일 때)

Block 2 패딩 (total N bytes, block 2에 M bytes 데이터):
- `0x80` + `0x00` × (55 - M) + 8-byte BE length(N * 8)

## 적용 조건 체크리스트

1. ☐ Hash oracle이 SHA256 (또는 다른 Merkle-Damgård 해시)?
2. ☐ 입력 길이를 블록 경계(64) 이상으로 확장 가능?
3. ☐ 확장된 입력의 특정 바이트 위치를 제어 가능?
4. ☐ 0x80, 0x00, length byte를 직접 주입할 수 있는 경로?
5. ☐ 한 블록짜리 입력의 해시를 별도로 수집 가능?

→ 모두 예 → SHA256 length extension via oracle 적용 가능

## 실전 예시: Sign In Please, Again (HKCERT CTF 2021)

- `set(pbox) == set(range(21))` — 길이 제한 없이 중복 인덱스 허용 → 65~66바이트 출력
- salt 4바이트 = `[0x00, pepper_i, 0x80, 0xA8]` → block 1에 SHA256 패딩 재현
- 49 calls: 16(h_targets) + 16(h_lookups) + 16(byte-by-byte) + 1(auth)
- ~65% 성공률 (random pepper가 0-15 범위에 있어야 매칭)

## 공통 함정

1. **Length extension ≠ hash collision**: 새 블록을 추가하는 것이지 같은 해시를 만드는 게 아님
2. **패딩의 length field는 전체 메시지 길이**: block 2의 length는 block 1 + block 2 합산
3. **hashlib은 intermediate state 설정 불가**: custom SHA256 구현 필요
4. **패딩 바이트 주입 경로 확인 필수**: 0x80과 length byte를 어떤 제어 변수로 넣을 수 있는지
