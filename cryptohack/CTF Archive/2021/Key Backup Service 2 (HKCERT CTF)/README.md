# Key Backup Service 2 (HKCERT CTF) (?pts)
## 2021

## Description
Mystiz is really lazy. He expects that someone would crack the bank-level encryption, but he doesn't care about that. After all, the darkest secret is not that dark. He decided to change the numbers and release it to the public again. Now crack it!Challenge contributed by MystizChallenge files:  - transcript.zip  - chall.py

## Files
- `transcript.zip`
- `chall.py`

## Solution
`ord(G) = 2^25` → 16384라운드에서 birthday collision (~4쌍). 충돌 쌍 (i,j)에서 `p = gcd(c2_i - c2_j, c3_i - c3_j)` (512-bit 소수). `master_secret = pow(cb % p, pow(e,-1,p-1), p)`. AES-CBC 복호화.

## Flag
`hkcert21{y0u_d0nt_n33d_p41rw15e_9cd_1f_y0u_c4n_d0_i7_1n_b4tch}`
