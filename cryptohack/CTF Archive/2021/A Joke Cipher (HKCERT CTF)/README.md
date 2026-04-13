# A Joke Cipher (HKCERT CTF) (?pts)
## 2021

## Description
In the beginning of 2020, Khaled A. Nagaty invented a cryptosystem based on key exchange. The cipher is faster than ever... It is impossible to break, right?Challenge contributed by MystizChallenge files:  - output.txt  - chall.py

## Files
- `output.txt`
- `chall.py`

## Solution
Nagaty shared key = `(y_A * y_B)^2 mod p`. 암호화는 `c = flag * shared_key` (모듈러 없음). `flag = c // shared_key`로 복호화.

## Flag
`hkcert21{th1s_i5_wh4t_w3_c4ll3d_sn4k3o1l_crypt0sy5t3m}`
