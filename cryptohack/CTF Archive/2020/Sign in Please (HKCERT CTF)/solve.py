#!/usr/bin/env python3
"""
Solve: HKCERT CTF 2020 - Sign in Please
Server: archive.cryptohack.org:1024

Attack Summary (SHA256 length-extension + rainbow table):

The server has a 16-byte base64 password.  spy(pbox, salt) returns
sha256(permutate(password+salt, pbox)), where pbox only needs 20 UNIQUE values
but can have any length (repeated values are allowed).

Key insight: pbox can be longer than 20 with repeated values.  We craft a
66-element pbox so that permutate returns a 66-byte string whose first 64 bytes
are IDENTICAL to the single 64-byte block SHA256 would process for our stage-1
query, and whose last 2 bytes are password[2j] and password[2j+1].

Stage 1  (1 spy call)
    pbox = [0..19], salt = [0, 160, 2, 128]
    Returns sha256(password + [0, 160, 2, 128]).
    SHA256 internally pads 20 bytes to exactly one 64-byte block:
        password(16B) + salt(4B) + 0x80 + 0x00*35 + 0x00000000000000A0
    The returned hash words become our custom initial state H1.

Stage 2  (8 spy calls, 2 password bytes recovered each)
    pbox = [0..19] + [19] + [16]*42 + [17] + [2j, 2j+1]   (j = 0..7)
    The 66-byte output from permutate is:
        password+salt (20B)          <- same as stage-1 block bytes 0-19
        salt[3]=0x80  (1B)           <- SHA256 padding byte, same as stage-1 byte 20
        salt[0]=0x00  (42B)          <- zeros, same as stage-1 bytes 21-62
        salt[1]=0xA0  (1B)           <- length byte, same as stage-1 byte 63
        password[2j], password[2j+1] <- 2 unknown bytes
    First 64 bytes == stage-1 padded block  =>
        SHA256 state after processing them == H1 (known!)
    Second block (bytes 64-127 after SHA256 pads to 128B):
        password[2j] + password[2j+1] + 0x80 + 0x00*53 + pack('>Q', 528)
    Only 64*64 = 4096 possibilities (base64 chars).
    Pre-build rainbow table; look up spy's returned hash to recover the pair.

Stage 9  (1 auth call)
    Server reveals random pbox_auth and salt_auth.
    Compute sha256(permutate(recovered_password + salt_auth, pbox_auth)) locally.
    Submit the hash to get the flag.

Total commands used: 1 + 8 + 1 = 10 (exactly the limit).
"""

import base64
import hashlib
import struct
import socket
import time

# ── SHA-256 constants and primitives ──────────────────────────────────────────

SHA256_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK32 = 0xFFFFFFFF


def _rotr32(x, n):
    return ((x << (32 - n)) & MASK32) | (x >> n)


def sha256_compress(block_bytes: bytes, state: list) -> list:
    """Process one 64-byte block starting from the given 8-word state."""
    assert len(block_bytes) == 64
    W = list(struct.unpack('>16I', block_bytes)) + [0] * 48
    for i in range(16, 64):
        w15 = W[i - 15]
        s0 = _rotr32(w15, 7) ^ _rotr32(w15, 18) ^ (w15 >> 3)
        w2 = W[i - 2]
        s1 = _rotr32(w2, 17) ^ _rotr32(w2, 19) ^ (w2 >> 10)
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & MASK32

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ ((~e & MASK32) & g)
        temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) & MASK32
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK32
        h, g, f, e, d, c, b, a = (
            g, f, e, (d + temp1) & MASK32,
            c, b, a, (temp1 + temp2) & MASK32,
        )
    return [(s + v) & MASK32 for s, v in zip(state, [a, b, c, d, e, f, g, h])]


def state_to_hex(state: list) -> str:
    return ''.join(f'{w:08x}' for w in state)


# ── Protocol helpers ──────────────────────────────────────────────────────────

def permutate(payload: bytes, pbox: list) -> bytes:
    return bytes(payload[x] for x in pbox)


def parse_pbox(s: str) -> list:
    return list(map(int, s.strip()[1:-1].split(',')))


# ── Network I/O ───────────────────────────────────────────────────────────────

class Server:
    def __init__(self, host: str, port: int):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.s.settimeout(10)
        self.buf = b''

    def _recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError('connection closed')
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        data, self.buf = self.buf[:idx], self.buf[idx:]
        return data

    def read_until(self, marker: str) -> str:
        return self._recv_until(marker.encode()).decode()

    def sendline(self, msg: str):
        self.s.sendall((msg + '\n').encode())
        time.sleep(0.05)

    def spy(self, pbox: list, salt: bytes) -> str:
        """Send a spy command, return the hex hash."""
        self.read_until('[cmd] ')
        self.sendline('spy')
        self.read_until('[pbox] ')
        self.sendline('[' + ','.join(map(str, pbox)) + ']')
        self.read_until('[salt] ')
        self.sendline(base64.b64encode(salt).decode())
        line = self.read_until('\n')
        # line looks like '[hash] <hexdigest>\n'
        return line.split('[hash] ')[1].strip()

    def auth(self):
        """Initiate auth, return (pbox, salt_bytes); ready to accept hash."""
        self.read_until('[cmd] ')
        self.sendline('auth')
        pbox_line = self.read_until('\n')
        pbox = parse_pbox(pbox_line.split('[pbox] ')[1])
        salt_line = self.read_until('\n')
        salt_b64 = salt_line.split('[salt] ')[1].strip()
        salt = base64.b64decode(salt_b64)
        self.read_until('[hash] ')
        return pbox, salt

    def send_hash(self, h: str) -> str:
        """Send the hash answer to a pending auth and read the server response."""
        self.sendline(h)
        resp = self.read_until('\n')
        return resp.strip()

    def close(self):
        self.s.close()


# ── Main attack ───────────────────────────────────────────────────────────────

def build_rainbow(h1_state: list) -> dict:
    """
    Build a rainbow table mapping sha256_with_state(H1, block2) -> (c1, c2)
    for all (c1, c2) pairs of base64 characters.

    block2 = c1 || c2 || 0x80 || 0x00*53 || pack('>Q', 66*8)
    (This is the second 64-byte SHA256 block of our 66-byte spy output.)
    """
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    suffix = b'\x80' + b'\x00' * 53 + struct.pack('>Q', 66 * 8)
    rainbow = {}
    for c1 in B64:
        for c2 in B64:
            block2 = c1.encode() + c2.encode() + suffix
            final = sha256_compress(block2, h1_state)
            rainbow[state_to_hex(final)] = c1 + c2
    return rainbow


def solve(host='archive.cryptohack.org', port=1024):
    # Fixed spy salt chosen so that the SHA256 padding of the 20-byte
    # spy output is all zeros except for a single 0x80 and the length
    # byte 0xA0 (= 160 bits), which happen to equal salt[3] and salt[1]
    # respectively -- making stage-2 block-1 identical to stage-1 block.
    SPY_SALT = bytes([0, 0xA0, 0x02, 0x80])

    srv = Server(host, port)

    # ── Stage 1: get H1 = sha256(password + SPY_SALT) ────────────────────────
    print('[*] Stage 1: retrieving SHA-256 initial state ...')
    pbox_id = list(range(20))          # identity permutation
    h1_hex = srv.spy(pbox_id, SPY_SALT)
    print(f'    H1 = {h1_hex}')
    h1_state = [int(h1_hex[i:i+8], 16) for i in range(0, 64, 8)]

    # ── Stage 1b: build rainbow table ────────────────────────────────────────
    print('[*] Building 4096-entry rainbow table ...')
    rainbow = build_rainbow(h1_state)
    print('    done.')

    # ── Stage 2: recover password 2 bytes at a time (8 calls) ────────────────
    # pbox layout (66 elements):
    #   [0..19]  -- identity (20): gives password+salt verbatim (block1 bytes 0-19)
    #   [19]     -- (1): salt[3] = 0x80  (block1 byte 20 = SHA-256 pad byte)
    #   [16]*42  -- (42): salt[0] = 0x00 (block1 bytes 21-62 = zeros)
    #   [17]     -- (1): salt[1] = 0xA0  (block1 byte 63 = length byte)
    #   [2j, 2j+1] -- (2): password bytes 2j and 2j+1 (block2 first two bytes)
    password = ''
    for j in range(8):
        pbox_j = list(range(20)) + [19] + [16] * 42 + [17] + [2 * j, 2 * j + 1]
        h_j = srv.spy(pbox_j, SPY_SALT)
        pair = rainbow.get(h_j)
        if pair is None:
            raise ValueError(f'Stage 2 j={j}: hash not found in rainbow table!')
        password += pair
        print(f'    j={j}  recovered bytes {2*j:2d}-{2*j+1:2d}: {pair!r}  '
              f'(running: {password!r})')

    print(f'[*] Recovered password: {password!r}')

    # ── Stage 3: auth ─────────────────────────────────────────────────────────
    print('[*] Stage 9: authenticating ...')
    pbox_auth, salt_auth = srv.auth()
    permuted = permutate(password.encode() + salt_auth, pbox_auth)
    h_auth = hashlib.sha256(permuted).hexdigest()
    result = srv.send_hash(h_auth)
    print(f'[+] Server response: {result}')
    srv.close()
    return result


if __name__ == '__main__':
    flag = solve()
    if 'flag' in flag.lower() or 'hkcert' in flag.lower():
        print(f'\n[FLAG] {flag}')
    else:
        print(f'\n[!] Unexpected response: {flag}')
