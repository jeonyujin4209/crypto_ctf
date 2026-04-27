"""
OR Proof - CTF Archive Challenge
archive.cryptohack.org:11840

The challenge has 3 parts:
1. Correctness: Prove you know w0 (or w1) using OR proof
2. Special Soundness: Extract witness from two transcripts with same commitment but different challenges
3. SHVZK: Simulate a satisfying transcript given s

Parameters from params.py:
- p = safe prime, q = (p-1)/2, g = 2
- w0 known (hardcoded), y0 = g^w0 mod p
- w1 unknown, y1 = g^w1 mod p (we only know y1)

OR Proof structure:
- Prover knows w_b for some b in {0,1}
- For branch 1-b (simulated): pick e_{1-b} random, pick z_{1-b} random, compute a_{1-b} = g^{z_{1-b}} * y_{1-b}^{-e_{1-b}} mod p
- For branch b (honest): pick r_b random, compute a_b = g^{r_b} mod p
- Send (a0, a1)
- Receive challenge s
- Set e_b = s XOR e_{1-b}
- Compute z_b = r_b + e_b * w_b mod q
- Send (e0, e1, z0, z1)

Verification:
- e0 XOR e1 == s
- g^z0 == a0 * y0^e0 mod p
- g^z1 == a1 * y1^e1 mod p
"""

import socket
import random
import sys

# Known parameters
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Known witness for y0
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

# Verify our w0
assert pow(g, w0, p) == y0, "w0 is wrong!"

HOST = 'archive.cryptohack.org'
PORT = 11840

class Connection:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(30)
        self.s.connect((HOST, PORT))
        self.buf = b''

    def recv_until(self, marker):
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Exception("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result

    def recv_line(self):
        return self.recv_until(b'\n').decode().strip()

    def send_int(self, n):
        self.s.sendall(str(n).encode() + b'\n')

    def send_str(self, s):
        self.s.sendall(s.encode() + b'\n')

def simulate_transcript(y, p, q, g):
    """Simulate a transcript for which we don't know the witness"""
    e_sim = random.randint(0, 2**511 - 1)
    z_sim = random.randint(0, q - 1)
    # a = g^z * y^{-e} mod p  => g^z = a * y^e
    a_sim = (pow(g, z_sim, p) * pow(y, -e_sim, p)) % p
    return a_sim, e_sim, z_sim

def correctness(conn):
    """Part 1: Prove we know w0"""
    print("[*] Correctness phase")
    # Read prompt
    conn.recv_until(b'a0:')

    # We know w0 (branch b=0), simulate branch b=1
    # Honest branch 0: pick r0
    r0 = random.randint(0, q - 1)
    a0 = pow(g, r0, p)

    # Simulate branch 1: pick e1, z1 random, compute a1 = g^z1 * y1^{-e1}
    e1_sim = random.randint(0, 2**511 - 1)
    z1_sim = random.randint(0, q - 1)
    a1 = (pow(g, z1_sim, p) * pow(y1, -e1_sim, p)) % p

    # Send a0, a1
    conn.send_int(a0)
    conn.recv_until(b'a1:')
    conn.send_int(a1)

    # Receive challenge s
    line = conn.recv_line()
    print(f"  Server: {line}")
    s = int(line.split('=')[1].strip())

    # Compute e0 = s XOR e1
    e0 = s ^ e1_sim
    # Compute z0 = r0 + e0 * w0 mod q
    z0 = (r0 + e0 * w0) % q
    e1 = e1_sim
    z1 = z1_sim

    # Verify locally
    assert e0 ^ e1 == s
    assert pow(g, z0, p) == (a0 * pow(y0, e0, p)) % p
    assert pow(g, z1, p) == (a1 * pow(y1, e1, p)) % p

    conn.recv_until(b'e0:')
    conn.send_int(e0)
    conn.recv_until(b'e1:')
    conn.send_int(e1)
    conn.recv_until(b'z0:')
    conn.send_int(z0)
    conn.recv_until(b'z1:')
    conn.send_int(z1)

    print("[+] Correctness done!")

def special_soundness(conn):
    """Part 2: Extract witness from two transcripts"""
    print("[*] Special Soundness phase")

    # Read: "i will now prove knowledge of w such that either g^w=y0 or g^w=y1 mod p"
    line = conn.recv_line()
    print(f"  {line}")
    # Read y0 and y1
    line = conn.recv_line()
    print(f"  {line}")
    y0_ss = int(line.split('=')[1].strip())
    line = conn.recv_line()
    print(f"  {line}")
    y1_ss = int(line.split('=')[1].strip())

    # Read "Special Soundness!"
    line = conn.recv_line()
    print(f"  {line}")

    # Read transcript 1
    line = conn.recv_line()  # "transcript 1:"
    print(f"  {line}")

    # Read a0, a1, s, e0, e1, z0, z1
    line = conn.recv_line()
    a0_t1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    a1_t1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    s1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    e0_t1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    e1_t1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    z0_t1 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    z1_t1 = int(line.split('=')[1].strip())

    print(f"  T1: a0={a0_t1}, a1={a1_t1}, s={s1}")
    print(f"  T1: e0={e0_t1}, e1={e1_t1}, z0={z0_t1}, z1={z1_t1}")

    # Read transcript 2
    line = conn.recv_line()  # "transcript 2:"
    print(f"  {line}")
    line = conn.recv_line()
    a0_t2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    a1_t2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    s2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    e0_t2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    e1_t2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    z0_t2 = int(line.split('=')[1].strip())
    line = conn.recv_line()
    z1_t2 = int(line.split('=')[1].strip())

    print(f"  T2: a0={a0_t2}, a1={a1_t2}, s*={s2}")
    print(f"  T2: e0={e0_t2}, e1={e1_t2}, z0={z0_t2}, z1={z1_t2}")

    # Extract witness from two transcripts
    # The two transcripts share a0=a0, a1=a1
    # One branch is simulated (same e,z), the other changes with different challenge
    #
    # If branch 0 was real (b=0), then:
    #   e0_t1 = s1 ^ e1_t1, e0_t2 = s2 ^ e1_t2
    #   z0_t1 = r0 + e0_t1 * w0, z0_t2 = r0 + e0_t2 * w0
    #   => z0_t1 - z0_t2 = (e0_t1 - e0_t2) * w0 mod q
    #   => w0 = (z0_t1 - z0_t2) * inverse(e0_t1 - e0_t2) mod q
    #
    # If branch 1 was real (b=1), then similarly for z1, e1

    # Try to extract from branch 0
    if e0_t1 != e0_t2:
        diff_e = (e0_t1 - e0_t2) % q
        diff_z = (z0_t1 - z0_t2) % q
        w_candidate = (diff_z * pow(diff_e, -1, q)) % q
        if pow(g, w_candidate, p) == y0_ss or pow(g, w_candidate, p) == y1_ss:
            print(f"[+] Extracted witness from branch 0: {w_candidate}")
            conn.recv_until(b'give me a witness!')
            conn.send_int(w_candidate)
            line = conn.recv_line()
            print(f"  {line}")
            return

    # Try to extract from branch 1
    if e1_t1 != e1_t2:
        diff_e = (e1_t1 - e1_t2) % q
        diff_z = (z1_t1 - z1_t2) % q
        w_candidate = (diff_z * pow(diff_e, -1, q)) % q
        if pow(g, w_candidate, p) == y0_ss or pow(g, w_candidate, p) == y1_ss:
            print(f"[+] Extracted witness from branch 1: {w_candidate}")
            conn.recv_until(b'give me a witness!')
            conn.send_int(w_candidate)
            line = conn.recv_line()
            print(f"  {line}")
            return

    print("[!] Failed to extract witness!")
    sys.exit(1)

def shvzk(conn):
    """Part 3: Simulate a satisfying transcript"""
    print("[*] SHVZK phase")

    line = conn.recv_line()  # "Finally, show me you can simulate proofs!"
    print(f"  {line}")

    line = conn.recv_line()
    print(f"  {line}")
    y0_sh = int(line.split('=')[1].strip())

    line = conn.recv_line()
    print(f"  {line}")
    y1_sh = int(line.split('=')[1].strip())

    line = conn.recv_line()
    print(f"  {line}")
    s = int(line.split('=')[1].strip())

    # Simulate: pick e0, z0, z1 random, compute a0 and a1
    # For branch 0: pick e0, z0 random, a0 = g^z0 * y0^{-e0}
    # For branch 1: e1 = s XOR e0, pick z1 random, a1 = g^z1 * y1^{-e1}
    e0 = random.randint(0, 2**511 - 1)
    e1 = s ^ e0

    z0 = random.randint(0, q - 1)
    z1 = random.randint(0, q - 1)

    a0 = (pow(g, z0, p) * pow(y0_sh, -e0, p)) % p
    a1 = (pow(g, z1, p) * pow(y1_sh, -e1, p)) % p

    # Verify locally
    assert e0 ^ e1 == s
    assert pow(g, z0, p) == (a0 * pow(y0_sh, e0, p)) % p
    assert pow(g, z1, p) == (a1 * pow(y1_sh, e1, p)) % p

    conn.recv_until(b'a0: ')
    conn.send_int(a0)
    conn.recv_until(b'a1: ')
    conn.send_int(a1)
    conn.recv_until(b'e0: ')
    conn.send_int(e0)
    conn.recv_until(b'e1: ')
    conn.send_int(e1)
    conn.recv_until(b'z0: ')
    conn.send_int(z0)
    conn.recv_until(b'z1: ')
    conn.send_int(z1)

    print("[+] SHVZK done!")

def main():
    print("[*] Connecting to OR Proof challenge...")
    conn = Connection()

    correctness(conn)
    special_soundness(conn)
    shvzk(conn)

    # Read remaining output (flag)
    try:
        remaining = conn.s.recv(4096)
        print(f"\n[+] Server response: {remaining.decode()}")
    except:
        pass

if __name__ == '__main__':
    main()
