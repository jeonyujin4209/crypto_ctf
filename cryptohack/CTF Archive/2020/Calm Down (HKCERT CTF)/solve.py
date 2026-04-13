"""
Calm Down (HKCERT CTF 2020) - RSA Last-Byte Oracle Binary Search

Oracle: send(c') → "nice" if decrypt(c')[-1] == b'.' (0x2e)

Key insight:
  The plaintext m ends with '.' (0x2e). Multiplying ciphertext by s^e mod n
  makes the server decrypt s*m mod n. If s ≡ 0x81 (mod 256), then:

  Property: 0x81 * 0x2e mod 256 = 129 * 46 mod 256 = 5934 mod 256 = 46 = 0x2e
  → Multiplying by s ≡ 0x81 is a "fixed point" on 0x2e mod 256.

  Case 1 (no overflow, s*m < n):
    (s*m mod n) mod 256 = (s*m) mod 256 = (0x81 * 0x2e) mod 256 = 0x2e → oracle True
  Case 2 (overflow, s*m ≥ n):
    (s*m mod n) mod 256 = (s*m - n) mod 256 = (0x2e - n_last) mod 256
    n is odd (RSA) → n_last ≠ 0 → result ≠ 0x2e → oracle False

  Oracle True  ↔  s*m < n  ↔  m < n/s   → upper bound update
  Oracle False ↔  s*m ≥ n  ↔  m ≥ n/s   → lower bound update

Binary search: ~2048 queries for 2048-bit n.
"""

import socket
import base64
import time
from Crypto.Util.number import bytes_to_long, long_to_bytes


HOST = 'archive.cryptohack.org'
PORT = 53580


class Server:
    def __init__(self):
        self.s = socket.socket()
        self.s.settimeout(5)
        self.s.connect((HOST, PORT))
        self._recv()

    def _recv(self):
        buf = b''
        while True:
            try:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b'[cmd]' in buf:
                    break
            except socket.timeout:
                break
        return buf.decode(errors='replace')

    def _send(self, cmd):
        self.s.sendall((cmd + '\n').encode())
        return self._recv()

    def get_n(self):
        resp = self._send('pkey')
        for line in resp.split('\n'):
            if '[pkey]' in line:
                return bytes_to_long(base64.b64decode(line.split('[pkey] ')[1].strip()))

    def get_ct(self):
        resp = self._send('read')
        for line in resp.split('\n'):
            if '[shhh]' in line:
                return bytes_to_long(base64.b64decode(line.split('[shhh] ')[1].strip()))

    def oracle(self, c_int, n):
        c_b64 = base64.b64encode(long_to_bytes(c_int % n)).decode()
        resp = self._send(f'send {c_b64}')
        return 'nice' in resp

    def close(self):
        self.s.close()


def recover_message(srv, n, ct, e=65537):
    """
    Binary search on m using the last-byte oracle.

    Invariant: m ∈ [lo, hi] throughout the search.
    Each step narrows the interval by approximately half.
    """
    # Verify: oracle(original ct) should be True (m ends with '.')
    if srv.oracle(ct, n):
        print("[+] Verified: original plaintext ends with '.'")
    else:
        print("[!] Warning: oracle on original ct returned False — unexpected!")

    lo = 0
    hi = n - 1

    step = 0
    while hi - lo > 1:
        mid = (lo + hi) // 2

        # Choose s ≈ ceil(n / mid), then adjust to s ≡ 0x81 (mod 256)
        # so that oracle distinguishes s*m < n vs s*m ≥ n
        s = (n + mid - 1) // mid       # ceil(n / mid)
        s += (0x81 - s % 256) % 256    # adjust last byte to 0x81

        # Threshold: largest m satisfying s*m < n
        t = (n - 1) // s  # = floor((n-1)/s)

        if not (lo <= t < hi):
            # Threshold outside our interval — skip this s, nudge slightly
            s += 256  # next multiple that ends in 0x81
            t = (n - 1) // s
            if not (lo <= t < hi):
                # Can't find good s, take a best-guess step
                hi = mid
                step += 1
                continue

        # Oracle query: True → s*m < n → m ≤ t
        #               False → s*m ≥ n → m ≥ t+1
        c_query = ct * pow(s, e, n) % n
        result = srv.oracle(c_query, n)

        if result:
            hi = t
        else:
            lo = t + 1

        step += 1
        if step % 100 == 0:
            print(f"  step {step:4d}: lo={lo.bit_length():4d}b, hi={hi.bit_length():4d}b, "
                  f"gap={( hi - lo).bit_length()}b")

    print(f"[+] Converged after {step} queries")
    return lo


def main():
    srv = Server()
    print("[*] Connected")

    n = srv.get_n()
    ct = srv.get_ct()
    print(f"[*] n = {n.bit_length()}-bit")
    print(f"[*] ct = {ct.bit_length()}-bit")

    m = recover_message(srv, n, ct)
    srv.close()

    flag_bytes = long_to_bytes(m)
    print(f"\n[+] m = {flag_bytes}")
    try:
        print(f"[+] Flag: {flag_bytes.decode()}")
    except Exception:
        print(f"[+] Flag (latin-1): {flag_bytes.decode('latin-1')}")


if __name__ == '__main__':
    main()
