# Cipher Mode Picker (HKCERT CTF) (?pts)
## 2021

## Description
Every slightest mistake in cryptography would lead to a disastrous result. Let's see what will happen when you allow end-users to pick the mode of operation...Challenge contributed by MystizConnect at archive.cryptohack.org 2951Challenge files:  - chall.py

## Files
- `chall.py`

## Solution
CFB-128에 zero plaintext를 암호화하면 OFB keystream과 동일. `cfb data <80 zeros>` → keystream, `ofb flag` → flag XOR keystream. XOR하면 flag 복원. (서버 연결 필요)
