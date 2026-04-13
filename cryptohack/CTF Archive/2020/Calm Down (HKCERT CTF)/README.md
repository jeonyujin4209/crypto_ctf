# Calm Down (HKCERT CTF) (?pts)
## 2020

## Description
I am so excited having a chance talking to Alice. She told me to calm down - and sent me an encrypted secret.Challenge contributed by MystizConnect at archive.cryptohack.org 53580Challenge files:  - chall.py

## Files
- `chall.py`

## Solution
RSA last-byte oracle binary search. m 자체가 `.`(0x2e)로 끝남 + `0x81 * 0x2e ≡ 0x2e (mod 256)` 고정점 성질 이용.
s ≡ 0x81 (mod 256) 인 승수 선택 시:
- **No overflow** (s*m < n): last byte = 0x2e → oracle True
- **Overflow** (s*m ≥ n): last byte = (0x2e − n_last) mod 256 ≠ 0x2e → oracle False
→ `oracle True ↔ m < n/s` 로 binary search. 총 ~2048 쿼리.

## Flag
`hkcert20{c4lm_d0wn_4nd_s0lv3_th3_ch4llen9e}`
