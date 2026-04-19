"""C0ll1d3r - Firebird Internal CTF 2022

Server: archive.cryptohack.org:9391
Vulnerability: hash(m) = pow(g, int('SECUREHASH_'||m), p) with (g, p) hidden.
  - Prefix 'SECUREHASH_' shared across all messages.
  - With two m of same length L differing only in last byte by delta, exponents
    M1 = PRE*256^L + int(m1), M2 = M1 + delta. So h2 = h1 * g^delta (mod p).
  - Sending m1..m4 with consecutive exponent differences 1,1,1 yields relations:
      h2^2 - h1*h3 ≡ 0 (mod p)     (both = g^(2M1+2))
      h3^2 - h2*h4 ≡ 0 (mod p)
      h2*h3 - h1*h4 ≡ 0 (mod p)
    gcd of these three 512-bit integers is p (modulo tiny cofactors).
  - Recover g = h2 * h1^{-1} mod p.

Collision: need m in [a-z]+ with M(m) ≡ M_target (mod p-1). Solve via BKZ/LLL
Kannan embedding of the modular knapsack sum(y_i * 256^(L-1-i)) ≡ E (mod p-1),
y_i ∈ [-12, 13] (centered alphabet shift).
"""
from pwn import remote, context
from math import gcd
from gmpy2 import is_prime
import subprocess
import os
import sys
import time

context.log_level = 'info'

HOST = 'archive.cryptohack.org'
PORT = 9391
PRE = int.from_bytes(b'SECUREHASH_', 'big')
TARGET = b'pleasegivemetheflag'
M_TARGET = int.from_bytes(b'SECUREHASH_' + TARGET, 'big')
HERE = os.path.dirname(os.path.abspath(__file__))


def query(r, m):
    r.sendline(m)
    line = r.recvline_contains(b'h(').decode()
    return int(line.split('= ')[1].strip(), 16)


def recover_p_g():
    r = remote(HOST, PORT)
    L0 = 10
    msgs = [b'a'*L0, b'a'*(L0-1) + b'b', b'a'*(L0-1) + b'c', b'a'*(L0-1) + b'd']
    hashes = []
    for m in msgs:
        h = query(r, m)
        hashes.append(h)
    h1, h2, h3, h4 = hashes
    X = h2*h2 - h1*h3
    Y = h3*h3 - h2*h4
    Z = h2*h3 - h1*h4
    p = gcd(gcd(X, Y), Z)
    for small in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while p % small == 0 and p // small > (1 << 240):
            p //= small
    assert is_prime(p) and 250 <= p.bit_length() <= 256, f'p bad: {p}'
    M1 = int.from_bytes(b'SECUREHASH_' + msgs[0], 'big')
    g = (h2 * pow(h1, -1, p)) % p
    assert pow(g, M1, p) == h1
    print(f'[+] p = {p} ({p.bit_length()} bits)')
    print(f'[+] g = {g}')
    return r, p, g


def find_collision(p):
    """Invoke sage docker to run LLL/BKZ collision search."""
    # HERE = 'D:/...'; convert to '/d/...' docker-style mount
    wd = HERE.replace('\\', '/')
    assert wd[1] == ':'
    mount_host = f'/{wd[0].lower()}{wd[2:]}'
    env = os.environ.copy()
    env['MSYS_NO_PATHCONV'] = '1'
    cmd = [
        'docker', 'run', '--rm',
        '-v', f'{mount_host}:/work',
        '-w', '/work',
        'sagemath/sagemath:latest',
        'sage', 'lll_collide.sage', str(p),
    ]
    print(f'[+] launching sage docker: {" ".join(cmd)}')
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1200)
    print(f'[+] sage took {time.time()-t0:.1f}s (rc={proc.returncode})')
    for line in proc.stdout.splitlines():
        if line.startswith('RESULT: '):
            return line[len('RESULT: '):].strip().encode()
    print('=== sage stdout ===')
    print(proc.stdout)
    print('=== sage stderr ===')
    print(proc.stderr)
    raise SystemExit('no RESULT line from sage')


def main():
    r, p, g = recover_p_g()
    # Verify target
    h_target_expected = pow(g, M_TARGET, p).to_bytes(32, 'big')
    print(f'[+] h_target = {h_target_expected.hex()}')

    m5 = find_collision(p)
    # Local verify
    M5 = int.from_bytes(b'SECUREHASH_' + m5, 'big')
    h5 = pow(g, M5, p).to_bytes(32, 'big')
    assert h5 == h_target_expected, f'local mismatch: {h5.hex()} vs {h_target_expected.hex()}'
    assert m5 != TARGET
    print(f'[+] m5 = {m5} ({len(m5)} bytes)')
    print(f'[+] local collision OK - sending')

    r.sendline(m5)
    print(r.recvall(timeout=5).decode(errors='replace'))


if __name__ == '__main__':
    main()
