"""import numpy as MT — Zh3r0 CTF V2 (2021)

Vulnerability: numpy.random.seed(32-bit int) has state[0] = seed directly (single-int path).
First random.bytes(16) triggers twist then packs 4 tempered state words LE.
Brute force 2^32 seeds, verify match on 4 untempered targets (state[0..3]_new) — in numba, ~2-3 min per round.

Cipher structure: out = iv1 || AES-CBC(k1,iv1, iv0 || AES-CBC(k0,iv0, pad(flag))).
Recover seed1 from iv1, decrypt → iv0 + C0; recover seed0 from iv0, decrypt → flag.
"""
from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from numpy import random
import sys

from mt_brute import find_seed


def fetch():
    r = remote('archive.cryptohack.org', 7265)
    data = bytes.fromhex(r.recvline().strip().decode())
    r.close()
    return data


def derive(seed):
    random.seed(seed)
    iv = random.bytes(16)
    key = random.bytes(16)
    return iv, key


def main():
    ct_hex = sys.argv[1] if len(sys.argv) > 1 else None
    if ct_hex:
        data = bytes.fromhex(ct_hex)
    else:
        data = fetch()
    print(f'[+] ciphertext {len(data)}B')

    # Layer 1 (outer)
    iv1 = data[:16]
    C1 = data[16:]
    print(f'[+] iv1={iv1.hex()}')
    print('[+] brute seed1...')
    seed1 = find_seed(iv1)
    assert seed1 is not None, 'seed1 not found'
    iv1_check, key1 = derive(seed1)
    assert iv1_check == iv1
    flag1 = AES.new(key1, AES.MODE_CBC, iv1).decrypt(C1)
    print(f'[+] flag1 ({len(flag1)}B)')

    # Layer 0 (inner)
    iv0 = flag1[:16]
    C0 = flag1[16:]
    print(f'[+] iv0={iv0.hex()}')
    print('[+] brute seed0...')
    seed0 = find_seed(iv0)
    assert seed0 is not None, 'seed0 not found'
    iv0_check, key0 = derive(seed0)
    assert iv0_check == iv0
    flag_padded = AES.new(key0, AES.MODE_CBC, iv0).decrypt(C0)
    flag = unpad(flag_padded, 16)
    print(f'[+] FLAG: {flag}')


if __name__ == '__main__':
    main()
