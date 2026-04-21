---
name: ecdsa-nonce-xor-d-hash-bit-lattice
description: ECDSA nonce k = d XOR z (d 비밀, z 메시지 해시)이면 k가 d의 비트에 선형이 되어 서명 congruence가 bit-level linear system mod q → Kannan embedding + LLL로 d 복구
type: attack
---

# ECDSA with Nonce = d XOR msg_hash: Bit-level Linear System + LLL

## 문제 유형

ECDSA signature에서 nonce `k`가 private key `d`와 message hash `z`의 **비트 단위 연산**으로 생성:

```python
def sign(z):
    k = d ^ z   # XOR
    r = (k * G).x
    s = pow(k, -1, q) * (z + r*d) % q
    return r, s
```

여러 서명 `(z_j, r_j, s_j)`가 주어지고 `d` 복구가 목표.

TSJ CTF 2022 "Signature"가 prototype. ecdsaPredictableNonce (jonasnick) 참조.

## 핵심 아이디어 (d의 비트가 linear)

### Step 1: XOR을 d의 비트에 대한 linear form으로 전개

`d = Σ_i d_i · 2^i`, `d_i ∈ {0,1}`. `z`의 bit `z_i`는 공개. 그러면:

$$
k = d \oplus z = \sum_i (d_i \oplus z_i) \cdot 2^i = z + \sum_i d_i \cdot 2^i \cdot (1 - 2 z_i)
$$

(유도: `d_i XOR z_i = d_i + z_i - 2·d_i·z_i`를 대입하고 `Σ z_i·2^i = z`.)

### Step 2: Signature congruence를 bit linear equation으로

`s·k ≡ z + r·d (mod q)`에 대입:

$$
\sum_i d_i \cdot 2^i \cdot [s \cdot (1 - 2 z_i) - r] \equiv z \cdot (1 - s) \pmod q
$$

서명 1개 → 256-bit modulus에서 선형 방정식 1개, 256개 binary 미지수 `d_i`.

계수 및 상수:
- `a_{j,i} = 2^i · (s_j · (1 - 2·z_{j,i}) - r_j) mod q`
- `c_j = z_j · (1 - s_j) mod q`

### Step 3: Kannan embedding lattice

`n_sig` 방정식 (예: 6개) + 256 bit 미지수. Lattice basis (dim = 256 + n_sig + 1):

```
Row i (0..255):   δ_i (256)     | K·a_{0,i}, ..., K·a_{n_sig-1,i} | 0
Row 256+j (0..n_sig-1):  0      | K·Q at j-th pos                 | 0
Row 262 (embed):  0             | K·c_0, ..., K·c_{n_sig-1}        | 1
```

`K = Q` 정도로 scaling. LLL 후 short vector `(d_0, ..., d_{255}, 0, ..., 0, -1)` 발견.

Norm: `√popcount(d) + 1 ≈ 11` (d가 256 bit, 평균 128 bit set).
Gaussian heuristic: `Q^{n_sig/dim} · √(dim/(2πe)) ≈ 2^{5.8} · 4 ≈ 240`. Target이 훨씬 짧아서 LLL이 즉시 찾음.

### Step 4: d 추출 및 검증

Reduced basis에서 `|last entry| == 1` 인 row:
- `last == -1`: `bits[i] = row[i]` (should be `{0,1}`)
- `last == +1`: `bits[i] = -row[i]`

각 서명에 대해 `s·(d XOR z) ≡ z + r·d mod q` 검증.

## 몇 개 서명이 필요한가

- `n_sig = 6`: 충분 (본 문제). Gaussian heuristic로 target이 1200배 짧음
- `n_sig = 3`: 경계. det(L) = Q^3 → GH ≈ Q^{3/262} ≈ 2^{2.9} ≈ 7.5. Target norm 11과 비슷 → 실패 가능
- 일반 규칙: `n_sig · log(Q) >> 256` 이면 무조건 풀림 (6개면 1536 >> 256 안전)

## 다른 bitwise 연산으로 일반화

`k = d ○ z` (○ 가 비트단위 연산)이면 대부분 유사하게 환원:

- **AND**: `(d AND z)_i = d_i · z_i`, so `k = Σ z_i · d_i · 2^i`. z_i=1 인 bit만 d에서 복구 가능 (z_i=0 이면 k에 안 섞임). 여러 서명 필요.
- **OR**: `(d OR z)_i = d_i + z_i - d_i · z_i`, linear in d_i.
- **NAND/NOR/XNOR**: 모두 `d_i`에 선형 → 같은 framework
- **z + d mod 2^256**: **carry 때문에 비선형** → 이 방법 안 됨 (다른 접근 필요)

## 구현 노트

### Sage XOR trap

`.sage` 파일에서 `^`는 `**`. XOR은 `^^` 또는 `int(d).__xor__(int(z))` 사용. 상세는 `sage-preparser-xor-trap`.

### Lattice scaling

`K = Q`로 시작. 너무 크면 LLL 시간 증가. 너무 작으면 모듈러 part가 short vector에 섞여 들어감. `K ≈ Q` 가 sweet spot.

### 대규모 d (512-bit, 1024-bit)

`d`가 크면 `n_sig` 늘려야 함. 일반적으로 `n_sig ≈ ⌈bitlen(d) / log(Q) · 2⌉` 정도로 여유있게.

### 대용량 scaling 주의

Sage `LLL()`은 integer LLL, 정확 연산. dim 263에 entries 512-bit 수준이면 ~15–30초. BKZ는 불필요.

## 왜 기존 HNP와 다른가

| 조건 | HNP (biased nonce) | 본 skill (bitwise nonce) |
|---|---|---|
| Leak 종류 | Nonce 크기 bias (MSB=0) | 비트별 구조적 관계 |
| Unknown | `d` + nonce magnitude | `d_i` binary vector |
| Lattice 구성 | `(r_i s_i^{-1}, s_i^{-1} z_i, W·d, W)` | bit-indexed 256 basis rows |
| 서명 수 | 3–5 (bias 클수록 적게) | `n_sig · log(Q) > bitlen(d)` |

## 부차 기술: AES-CTR nonce 없이 복호화

관련 CTF들은 AES-CTR 키 복구 후에도 pycryptodome `AES.new(key, MODE_CTR)`의 nonce(8 byte random)가 출력에 없어 막힘. **Known plaintext 16 byte 이상**이면:

```python
key = sha256(str(d).encode()).digest()[:16]
ks0 = bytes(a ^ b for a, b in zip(ct[:16], known_pt[:16]))
iv = AES.new(key, AES.MODE_ECB).decrypt(ks0)  # ks0 = AES_ECB_enc(key, IV)
nonce = iv[:8]
assert iv[8:] == b"\x00" * 8   # counter init = 0, 확인용
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
pt = cipher.decrypt(ct)
```

`"Congrats! This is your flag: "` 같은 정형 prefix가 있으면 자동.

## 출처

- CryptoHack CTF Archive 2022 TSJ CTF: Signature (maple3142) — secp256k1, `k = d XOR z`, 6 sigs
- Flag link: https://github.com/jonasnick/ecdsaPredictableNonce

## 실측 성능

- TSJ Signature (dim 263, Q=256-bit, n_sig=6): LLL 18초, 전체 22초
- Sage docker 환경, Windows host
