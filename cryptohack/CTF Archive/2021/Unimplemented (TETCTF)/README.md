# Unimplemented (TETCTF) (?pts)
## 2021

## Description
A new public key encryption algorithm is being invented, but the author is not quite sure how to implement the decryption routine correctly. Can you help him?Challenge contributed by NDHChallenge files:  - output.txt  - source.py

## Files
- `output.txt`
- `source.py`

## Solution
Gaussian integer RSA: `n = p^2 * q^2`, `e = 65537`. `p, q`는 output에 직접 제공. `lambda(Z[i]/(p^2)) = p*(p-1)` (p≡1 mod 4), `q*(q^2-1)` (q≡3 mod 4). LCM으로 `d` 계산 후 복호화.

## Flag
`TetCTF{c0unt1ng_1s_n0t_4lw4ys_34sy-vina:*100*48012023578024#}`
