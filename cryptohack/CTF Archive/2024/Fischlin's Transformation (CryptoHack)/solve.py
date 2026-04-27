"""
Fischlin's Transformation - CTF Archive Challenge
archive.cryptohack.org:3583

Vulnerability: WI break of Fischlin-transformed Sigma-OR proof via search-position leak.

In fischlin_proof(w0, w1, y0, y1, b):
  - For b=0 (w0 is real): e1=e_sim FIXED, z1=z_sim FIXED.
    Loop searches e in 0..1023: e0 = e XOR e1, z0 = r0 + e0*w0 mod q.
    Stops at first e where RO < 2^(512-B).
  - For b=1 (w1 is real): e0=e_sim FIXED, z0=z_sim FIXED.
    Loop searches e in 0..1023: e1 = e XOR e0, z1 = r1 + e1*w1 mod q.

Detection (always request w0 from leak_witness oracle):
  Compute count_b0_hits over e' in [0..e_proof] reconstructing what z0' would
  be IF b=0 with the leaked w0 and the recovered r0 = z0 - e0*w0 (mod q).
  - If b=0 truly: only e' = e_proof is a real hit -> count == 1 always.
  - If b=1: z0' values are garbage -> each e' < e_proof hits with prob 1/64.
    => count > 1 with high probability when e_proof is large.

Strategy across 16 attempts per round:
  - count > 1  -> definitely b=1 (commit, guess 1)
  - count == 1 -> ambiguous; skip (next attempt). On 16th attempt, guess b=0.
Failure rate ~12% per 64-round run; retry up to 10x.
"""

import socket
import json
from hashlib import sha512
from Crypto.Util.number import bytes_to_long

HOST = 'archive.cryptohack.org'
PORT = 3583

# DH parameters from params.py
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

B = 6


def RO(a0, a1, e, e0, e1, z0, z1):
    h = sha512(b'my')
    h.update(str(a0).encode()); h.update(b'very')
    h.update(str(a1).encode()); h.update(b'cool')
    h.update(str(e).encode());  h.update(b'random')
    h.update(str(e0).encode()); h.update(b'oracle')
    h.update(str(e1).encode()); h.update(b'for')
    h.update(str(z0).encode()); h.update(b'fischlin')
    h.update(str(z1).encode())
    return bytes_to_long(h.digest())


def count_hits_b0(w0, proof):
    a0 = proof['a0']; a1 = proof['a1']
    e_win = proof['e']
    e0_win = proof['e0']; e1_win = proof['e1']
    z0_win = proof['z0']; z1_win = proof['z1']

    r0 = (z0_win - e0_win * w0) % q
    threshold = 2 ** (512 - B)
    count = 0
    for ep in range(e_win + 1):
        e0p = ep ^ e1_win
        z0p = (r0 + e0p * w0) % q
        if RO(a0, a1, ep, e0p, e1_win, z0p, z1_win) < threshold:
            count += 1
    return count


class Conn:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(120)
        self.s.connect((HOST, PORT))
        self.buf = b''

    def recv_line(self):
        while b'\n' not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Exception("conn closed")
            self.buf += chunk
        idx = self.buf.index(b'\n') + 1
        line = self.buf[:idx]
        self.buf = self.buf[idx:]
        return line.decode().rstrip('\n').rstrip('\r')

    def send_line(self, msg):
        self.s.sendall(str(msg).encode() + b'\n')

    def recv_all(self, t=5):
        self.s.settimeout(t)
        data = self.buf
        self.buf = b''
        while True:
            try:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        return data.decode(errors='replace')


def parse_int(line, key):
    return int(line.split('=', 1)[1].strip())


def solve_one_run():
    print(f"[*] Connecting to {HOST}:{PORT}...")
    conn = Conn()

    for round_num in range(64):
        print(f"=== Round {round_num} ===")
        conn.recv_line()  # "round: N"
        conn.recv_line()  # "I will prove knowledge..."

        b_guess = None

        for attempt in range(16):
            conn.recv_line()  # y0 = ...
            conn.recv_line()  # y1 = ...

            conn.send_line(0)  # request w0
            line = conn.recv_line()  # "which witness do you want to see?w0 = ..."
            # Strip the prompt prefix if present
            if 'w0' in line:
                w0 = int(line.split('w0', 1)[1].split('=', 1)[1].strip())
            else:
                w0 = parse_int(line, 'w0')

            conn.recv_line()  # "here is your fishlin transcript"
            proof_line = conn.recv_line()
            proof = json.loads(proof_line)

            count = count_hits_b0(w0, proof)
            e_proof = proof['e']

            if count != 1:
                print(f"  Attempt {attempt}: e={e_proof}, count={count} -> GUESS b=1")
                conn.send_line('y')
                b_guess = 1
                break
            else:
                if attempt == 15:
                    print(f"  Attempt {attempt}: e={e_proof}, count=1 (LAST) -> guess b=0")
                    conn.send_line('y')
                    b_guess = 0
                else:
                    conn.send_line('n')

        conn.send_line(b_guess)
        result_line = conn.recv_line()
        print(f"  Result: {result_line[:120]}")

        if 'skill issue' in result_line.lower() or "didn't guess" in result_line.lower():
            print("[!] WRONG. Round failed.")
            return False

        next_line = conn.recv_line()
        print(f"  {next_line[:160]}")
        if 'crypto{' in next_line:
            print(f"\n[+] FLAG: {next_line}")
            return next_line

    # All 64 rounds done
    rest = conn.recv_all()
    print(f"  Tail: {rest[:300]}")
    for ln in rest.splitlines():
        if 'crypto{' in ln:
            return ln
    return True


def main():
    for attempt in range(10):
        print(f"\n{'='*50}\nConnection attempt {attempt+1}\n{'='*50}")
        try:
            r = solve_one_run()
            if r:
                if isinstance(r, str) and 'crypto{' in r:
                    print(f"\n[+] FLAG: {r}")
                print("[+] SUCCESS")
                return
            print("[!] retry...")
        except Exception as e:
            print(f"[!] err: {e}")
            import traceback; traceback.print_exc()

    print("[!] gave up after 10 tries")


if __name__ == '__main__':
    main()
