"""
Fischlin's Transformation - CTF Archive Challenge
archive.cryptohack.org:3583

Attack: Breaking Witness Indistinguishability via the Fischlin search structure.

In fischlin_proof(w0, w1, y0, y1, b):
  - For b=0 (w0 is real): e1=e_sim FIXED, z1=z_sim FIXED.
    The loop searches over e=0..1023: e0 = e XOR e1, z0 = r + e0*w0 mod q
    Stops at first e where RO < 2^(512-B).
  - For b=1 (w1 is real): e0=e_sim FIXED, z0=z_sim FIXED.
    The loop searches over e=0..1023: e1 = e XOR e0, z1 = r + e1*w1 mod q.

Detection using known w0 (count_b0 test):
  r_cand = (z0 - e0*w0) mod q
  For e' in [0..e_proof]:
    z0' = (r_cand + (e' XOR e1)*w0) % q
    Check RO(a0, a1, e', e' XOR e1, e1, z0', z1) < 2^(512-B)

  If b=0: z0' at e'=e_proof is exact match; all earlier e' were non-hits (first success).
    => count == 1 ALWAYS.
  If b=1: The z0' values are "garbage". Each e'<e_proof hits with independent prob 1/64.
    => count > 1 with probability 1-(63/64)^e_proof (often decisive for large e_proof).

Strategy: Always request w0. Compute count_b0.
  count > 1: CERTAINLY b=1 (break, guess 1)
  count == 1: ambiguous; skip unless last of 16 attempts (then guess b=0, 73% correct)

Expected ~2% of rounds reach all-16-ambiguous state.
Expected ~12% failure per full 64-round run; retry up to 10x.
"""

import socket
import json
from hashlib import sha512
from Crypto.Util.number import bytes_to_long

HOST = 'archive.cryptohack.org'
PORT = 3583

# DH parameters
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

B = 6  # Leading zero bits required


def RO(a0, a1, e, e0, e1, z0, z1):
    """Replicate the server's 'Totally_a_random_oracle' function."""
    ROstep = sha512(b'my')
    ROstep.update(str(a0).encode())
    ROstep.update(b'very')
    ROstep.update(str(a1).encode())
    ROstep.update(b'cool')
    ROstep.update(str(e).encode())
    ROstep.update(b'random')
    ROstep.update(str(e0).encode())
    ROstep.update(b'oracle')
    ROstep.update(str(e1).encode())
    ROstep.update(b'for')
    ROstep.update(str(z0).encode())
    ROstep.update(b'fischlin')
    ROstep.update(str(z1).encode())
    return bytes_to_long(ROstep.digest())


def count_hits_b0_hypothesis(w0, proof):
    """
    Count hits under b=0 hypothesis (w0 is the real witness for branch 0).
    For b=0: e1=e_sim (fixed), z1=z_sim (fixed).
    The loop varies e0=e^e1, z0=r0+e0*w0.
    r0 = z0_win - e0_win * w0 (mod q)

    For REAL b=0: exactly 1 hit (at e_win only).
    For FAKE b=0 (b=1): garbage RO values, ~Binomial(e_win, 1/64) + 1 hits.
    """
    a0 = proof['a0']
    a1 = proof['a1']
    e_win = proof['e']
    e0_win = proof['e0']
    e1_win = proof['e1']  # e_sim (fixed) for b=0
    z0_win = proof['z0']
    z1_win = proof['z1']  # z_sim (fixed) for b=0

    r0 = (z0_win - e0_win * w0) % q
    count = 0
    threshold = 2 ** (512 - B)
    for ep in range(e_win + 1):
        e0p = ep ^ e1_win
        z0p = (r0 + e0p * w0) % q
        h = RO(a0, a1, ep, e0p, e1_win, z0p, z1_win)
        if h < threshold:
            count += 1
    return count


def count_hits_b1_hypothesis(w1, proof):
    """
    Count hits under b=1 hypothesis (w1 is the real witness for branch 1).
    For b=1: e0=e_sim (fixed), z0=z_sim (fixed).
    The loop varies e1=e^e0, z1=r1+e1*w1.
    r1 = z1_win - e1_win * w1 (mod q)

    For REAL b=1: exactly 1 hit (at e_win only).
    For FAKE b=1 (b=0): garbage RO values, ~Binomial(e_win, 1/64) + 1 hits.
    """
    a0 = proof['a0']
    a1 = proof['a1']
    e_win = proof['e']
    e0_win = proof['e0']  # e_sim (fixed) for b=1
    e1_win = proof['e1']
    z0_win = proof['z0']  # z_sim (fixed) for b=1
    z1_win = proof['z1']

    r1 = (z1_win - e1_win * w1) % q
    count = 0
    threshold = 2 ** (512 - B)
    for ep in range(e_win + 1):
        e1p = ep ^ e0_win
        z1p = (r1 + e1p * w1) % q
        h = RO(a0, a1, ep, e0_win, e1p, z0_win, z1p)
        if h < threshold:
            count += 1
    return count


class Connection:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(120)
        self.s.connect((HOST, PORT))
        self.buf = b''

    def recv_until(self, marker):
        if isinstance(marker, str):
            marker = marker.encode()
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Exception("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result.decode()

    def recv_line(self):
        return self.recv_until(b'\n').strip()

    def send_line(self, msg):
        self.s.sendall(str(msg).encode() + b'\n')

    def recv_all(self):
        self.s.settimeout(5)
        data = b''
        while True:
            try:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        return data.decode()


def parse_value(line, key):
    """Parse 'key = value' from a line."""
    if '=' in line:
        return int(line.split('=', 1)[1].strip())
    return None


def solve_one_run():
    print(f"[*] Connecting to {HOST}:{PORT}...")
    conn = Connection()

    for round_num in range(64):
        print(f"\n=== Round {round_num} ===")

        # Read round header
        line = conn.recv_line()
        print(f"  {line}")
        line = conn.recv_line()
        # "I will prove knowledge..."

        last_proof = None
        last_witness = None
        last_witness_type = None
        b_guess = None

        for attempt in range(16):
            # Read y0
            line = conn.recv_line()
            # Read y1
            conn.recv_line()

            # Always request w0 to check b=0 hypothesis
            conn.send_line(0)
            line = conn.recv_line()
            w0 = parse_value(line, 'w0')

            # Read the proof JSON
            conn.recv_line()  # "here is your fishlin transcript"
            line = conn.recv_line()  # JSON proof
            proof = json.loads(line)

            # Check b=0 hypothesis
            count = count_hits_b0_hypothesis(w0, proof)
            e_proof = proof['e']

            if count != 1:
                # count > 1: b=0 hypothesis is inconsistent -> b=1 with certainty
                print(f"  Attempt {attempt}: e={e_proof}, count={count} -> GUESS b=1")
                conn.send_line('y')
                b_guess = 1
                break
            else:
                # count == 1: ambiguous; b=0 or b=1 with no extra false hits
                if attempt == 15:
                    # Last attempt: Bayesian guess b=0 (73% correct)
                    print(f"  Attempt {attempt}: e={e_proof}, count=1 -> LAST, guess b=0")
                    conn.send_line('y')
                    b_guess = 0
                else:
                    print(f"  Attempt {attempt}: e={e_proof}, count=1 -> skip")
                    conn.send_line('n')

        # Make the final guess
        conn.send_line(b_guess)

        # Read result (may have multiple lines)
        result_line = conn.recv_until(b'\n').strip()
        print(f"  Result: {result_line}")

        if 'skill issue' in result_line.lower() or "didn't guess" in result_line.lower():
            print("[!] WRONG GUESS! Round failed.")
            remaining = conn.recv_all()
            if remaining:
                print(remaining)
            return False

        # Read "do it X times more for flag!" OR the actual flag on last round
        line = conn.recv_line()
        print(f"  {line}")
        if 'crypto{' in line:
            print(f"\n[+] FLAG: {line}")
            return True

    # Read the final flag messages
    print("\n[+] All 64 rounds completed!")
    try:
        line1 = conn.recv_line()  # "well done, you distinguished all the witnesses!"
        print(f"  {line1}")
        line2 = conn.recv_line()  # FLAG
        print(f"  {line2}")
        if 'crypto{' in line2:
            print(f"\n[+] FLAG: {line2}")
        elif 'crypto{' in line1:
            print(f"\n[+] FLAG: {line1}")
    except Exception as e:
        print(f"  Error reading flag: {e}")
        remaining = conn.recv_all()
        print(f"  Remaining: {remaining}")
    return True


def main():
    for attempt in range(10):
        print(f"\n{'='*50}")
        print(f"Connection attempt {attempt + 1}")
        print(f"{'='*50}")
        try:
            if solve_one_run():
                print("[+] SUCCESS!")
                return
            print(f"[!] Failed, retrying...")
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()

    print("[!] Failed after 10 attempts")


if __name__ == '__main__':
    main()
