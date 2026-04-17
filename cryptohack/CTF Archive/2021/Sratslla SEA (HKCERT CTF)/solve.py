"""
Sratslla SEA (HKCERT CTF 2021)

AES-128 oracle with individual component disabling. 128 queries to recover 16-byte key.

Attack per disabled component:
1. No ARK (1 call): key-independent encryption → decrypt with zero key to get plaintext = key bytes.
2. No SB (2 calls): linear cipher → Enc(m)=S*m+T_k. XOR of Dec_0(Enc(0)) and Dec_0(Enc(secret))
   cancels T_k, yielding secret directly.
3. No MC (65 calls): no byte diffusion → byte k maps to byte (9k%16). Lookup table via 64 queries.
4. No SR (60 calls): column-independent → 59 lookups + brute-force remaining candidates.
"""
import sys, os, re, itertools

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwn import remote
from aes import AES

no_op = lambda *x: None

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

HOST = 'archive.cryptohack.org'
PORT = 36161


def solve():
    r = remote(HOST, PORT, timeout=10)

    # Parse encrypted flag (64 bytes = 128 hex chars)
    line = r.recvline().decode()
    c_flag = bytes.fromhex(re.search(r'[0-9a-f]{128}', line).group())

    key = [0] * 16

    # === Stage 1: ark secret (1 call) ===
    # No AddRoundKey → encryption is key-independent
    # Decrypt ciphertext with zero key (also skip ARK) to get plaintext = secret
    r.sendlineafter(b'> ', b'ark secret')
    c = bytes.fromhex(r.recvline().decode().strip())

    cipher = AES(b'\x00' * 16)
    cipher._add_round_key = no_op
    m = cipher.decrypt(c)
    assert m[0::4] == m[1::4] == m[2::4] == m[3::4]
    key[0:4] = list(m[0::4])
    print(f'[+] k[0:4] = {key[0:4]}')

    # === Stage 2: sb data(0) + sb secret (2 calls) ===
    # No SubBytes → entirely linear: Enc(m) = S*m + T_k
    # Dec_0(Enc(0)) XOR Dec_0(Enc(secret)) = S^{-1}(S*secret) = secret
    r.sendlineafter(b'> ', b'sb data ' + b'00' * 16)
    c0 = bytes.fromhex(r.recvline().decode().strip())

    r.sendlineafter(b'> ', b'sb secret')
    c1 = bytes.fromhex(r.recvline().decode().strip())

    cipher = AES(b'\x00' * 16)
    cipher._inv_sub_bytes = no_op
    m = xor(cipher.decrypt(c0), cipher.decrypt(c1))
    assert m[0::4] == m[1::4] == m[2::4] == m[3::4]
    key[4:8] = list(m[0::4])
    print(f'[+] k[4:8] = {key[4:8]}')

    # === Stage 3: mc data x64 + mc secret (65 calls) ===
    # No MixColumns → each byte independent, byte k maps to byte (9k % 16)
    # 64 messages cover all 256 byte values (4 per message)
    cs_mc = []
    for i in range(64):
        m_bytes = bytes([4 * i + j % 4 for j in range(16)])
        r.sendlineafter(b'> ', b'mc data ' + m_bytes.hex().encode())
        c = bytes.fromhex(r.recvline().decode().strip())
        # Rearrange so position k in rearranged = byte that came from plaintext position k
        c = bytes([c[9 * k % 16] for k in range(16)])
        cs_mc.append(c)

    r.sendlineafter(b'> ', b'mc secret')
    c_mc = bytes.fromhex(r.recvline().decode().strip())
    c_mc_r = [c_mc[9 * i % 16] for i in range(16)]

    for i in range(64):
        for j in range(16):
            if cs_mc[i][j] == c_mc_r[j]:
                key[12 + j // 4] = 4 * i + j % 4
    print(f'[+] k[12:16] = {key[12:16]}')

    # === Stage 4: sr data x59 + sr secret (60 calls) ===
    # No ShiftRows → each column (4 bytes) independent
    # 59 lookups, brute-force remaining 197 candidates per unmatched column
    cs_sr = []
    for i in range(59):
        m_bytes = bytes([i]) * 16
        r.sendlineafter(b'> ', b'sr data ' + m_bytes.hex().encode())
        c = bytes.fromhex(r.recvline().decode().strip())
        cs_sr.append(c)

    r.sendlineafter(b'> ', b'sr secret')
    c_sr = bytes.fromhex(r.recvline().decode().strip())

    r.close()

    # Match columns and build candidate lists
    matched = 0
    candidates = [list(range(59, 256)) for _ in range(4)]
    for i in range(59):
        for j in range(4):
            if cs_sr[i][4 * j:4 * j + 4] == c_sr[4 * j:4 * j + 4]:
                candidates[j] = [i]
                matched += 1

    total = 1
    for c in candidates:
        total *= len(c)
    print(f'[+] sr: {matched}/4 matched. Search space: {total}')

    if total > 500000:
        print(f'[-] Search space too large ({total}). Retrying...')
        return False

    # Brute-force remaining key bytes
    from Crypto.Cipher import AES as RealAES

    for subkey in itertools.product(*candidates):
        key[8:12] = list(subkey)
        cipher = RealAES.new(bytes(key), RealAES.MODE_ECB)
        m = cipher.decrypt(c_flag)
        if b'hkcert21{' in m:
            print(f'[+] Flag: {m.decode()}')
            return True

    print('[-] No flag found in search space.')
    return False


if __name__ == '__main__':
    while not solve():
        print('[*] Retrying...\n')
