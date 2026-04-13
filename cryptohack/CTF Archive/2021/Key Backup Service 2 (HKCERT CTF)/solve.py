"""
Key Backup Service 2 (HKCERT CTF 2021)

ord(G) mod N = 2^25 (small group order).
With 16384 rounds, birthday paradox gives ~4 pairs of rounds sharing the same
DH_G value, meaning they use the same 512-bit prime p in RSA key generation.

If round i and round j share prime p:
  c2_i ≡ 2^e (mod p)   and   c2_j ≡ 2^e (mod p)
  => p | (c2_i - c2_j) and p | (c3_i - c3_j)
  => p = gcd(c2_i - c2_j, c3_i - c3_j)

Since master_secret is 256-bit and p is 512-bit: master_secret < p
  => master_secret = pow(cb % p, pow(e, -1, p-1), p)

Attack: batch GCD over all O(n^2) pairs. Found collision at (7265, 11437).
"""
from math import gcd
from sympy import isprime
from Crypto.Cipher import AES

with open('transcript_out/transcript.log') as f:
    lines = f.read().splitlines()

flag_enc = bytes.fromhex(lines[1])
c2_list, c3_list, cb_list = [], [], []
i = 2
while i < len(lines):
    if (lines[i].startswith('[cmd] pkey') and i+6 < len(lines)
            and lines[i+1].startswith('[cmd] send 2')
            and lines[i+3].startswith('[cmd] send 3')
            and lines[i+5].startswith('[cmd] backup')):
        c2_list.append(int(lines[i+2], 16))
        c3_list.append(int(lines[i+4], 16))
        cb_list.append(int(lines[i+6], 16))
        i += 7
    else:
        i += 1

print(f"Total rounds: {len(c2_list)}")

# Known collision pair (found via full O(n^2) search)
# ord(G) = 2^25, so birthday collision expected in ~2*sqrt(2^25) = 2^13.5 ~ 11585 rounds
ci, cj = 7265, 11437
d2 = c2_list[ci] - c2_list[cj]
d3 = c3_list[ci] - c3_list[cj]
p = gcd(d2, d3)
assert p.bit_length() == 512 and isprime(p), "p recovery failed"
print(f"Recovered prime p ({p.bit_length()} bits)")

e = 65537
d_p = pow(e, -1, p - 1)
ms_int = pow(cb_list[ci] % p, d_p, p)
master_secret = ms_int.to_bytes(32, 'big')

cipher = AES.new(master_secret, AES.MODE_CBC, b'\x00' * 16)
flag = cipher.decrypt(flag_enc)
print("Flag:", flag.rstrip(b'\x00\x01\x02\x03'))
