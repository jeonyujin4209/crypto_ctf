---
name: ed25519-magic-malleability-and-identity-key
description: python-ed25519 (SUPERCOP ref10) 두 가지 magic 공격 — (1) S+L signature malleability (서로 다른 sig가 같은 msg 검증), (2) identity verifying key + identity-R + zero-S로 임의 메시지 검증 통과
type: attack
---

Warner의 `python-ed25519` (`pip install ed25519`) wrapper는 SUPERCOP ref10 검증기를 그대로 호출. ref10는 **`S < L` 검사 안 함** + **identity public key 거부 안 함** + **cofactored 검증(`[8]·` 곱) 안 함**. RFC 8032 §5.1.7 (canonical S, low-order rejection) 다 빠져있음.

## Attack 1 — Signature malleability (S + L)

검증기 코드:
```c
sm[63] & 224 → reject (S 상위 3비트 0 강제: S < 2^253)
sc_reduce(h);                                       // h mod L
ge_double_scalarmult_vartime(&R, h, &A, sm + 32);   // R' = h*A + s*B
crypto_verify_32(rcheck, sm)                        // R' == R
```

`sc_reduce`가 내부적으로 S mod L 계산. 그래서 `S' = S + L`도 같은 결과. 단 `S' < 2^253` 만 만족하면 됨.

```python
L = 2**252 + 27742317777372353535851937790883648493
sig = R || S         # original
S_int = int.from_bytes(S, "little")
S_new = S_int + L    # < 2L < 2^253 always
sig_new = R + S_new.to_bytes(32, "little")  # ≠ sig, but verify(sig_new, msg) → True
```

**언제 쓰나**: "원본과 다른 signature 제출하라" challenge (ed25519 magic Lv1).

## Attack 2 — Identity verifying key (universal forgery)

검증식: `R' = h*A + s*B`, `R' == R` 검사.

`A = identity` (Edwards (0, 1)) 잡으면 `h*A = identity` for **모든 h** (그래서 메시지/h 무관!). `s = 0`이면 `s*B = identity`. `R = identity` 잡으면 `R' = identity = R` ✓.

Identity encoding (Ed25519 little-endian y + x sign bit):
- y = 1 → bytes `01 00 ... 00` (32B)
- x = 0 (sign bit 0) → byte 31의 MSB = 0
- 즉 `vk = b'\x01' + b'\x00'*31`

Sig = R || S:
- R = identity bytes = `01 00 ... 00` (32B)
- S = 0 (32 zero bytes)
- 합쳐서 `b'\x01' + b'\x00'*63` (64B)

```python
vk_bytes  = b'\x01' + b'\x00' * 31
sig_bytes = b'\x01' + b'\x00' * 31 + b'\x00' * 32  # R(identity) || S(0)
# vk_bytes로 만든 verifying_key는 ANY 16-byte msg에 sig_bytes 통과.
```

**언제 쓰나**: 서버가 (msg를 우리에게 안 보여주고) `vk + sig` 받아 검증만 하면 됨 (ed25519 magic Lv2). msg가 `os.urandom(16)`이라 알 수 없어도 통과.

## Library 동작 차이 (중요)

| Library | malleability | identity vk | low-order reject |
|---|---|---|---|
| `ed25519` (Warner, pip install ed25519) | **OK** | **OK** | 없음 |
| `pure25519` (pure Python) | OK (S+L) | **REJECT** ("element was Zero") | 부분적 (RFC 8032 §5.1.7 일부) |
| `cryptography` (PyCA) | reject (>= 41) | reject | reject |
| `pynacl` (libsodium) | reject | reject | reject |

challenge가 `import ed25519` (pip)면 두 공격 다 작동. `pure25519` 또는 `nacl`이면 Attack 2 막힘.

## 로컬 검증 팁

`pip install ed25519` Windows에서 빌드 실패 (MSVC 필요). Docker로 우회:
```bash
docker run --rm -it ubuntu:20.04 bash
apt install python3-pip && pip install ed25519
```

## 테스트 코드

```python
import ed25519, base64, os
sk, vk = ed25519.create_keypair()
sig = sk.sign(b"CryptoHack")
L = 2**252 + 27742317777372353535851937790883648493
R, S = sig[:32], sig[32:]
S2 = (int.from_bytes(S, "little") + L).to_bytes(32, "little")
vk.verify(R + S2, b"CryptoHack")  # malleability OK

vk2 = ed25519.VerifyingKey(b"\x01" + b"\x00"*31)
vk2.verify(b"\x01" + b"\x00"*63, os.urandom(16))  # identity attack OK
```
