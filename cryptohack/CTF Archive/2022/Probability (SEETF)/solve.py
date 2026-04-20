"""
Probability (SEETF) — MT19937 PRNG prediction via Z3 + graph DP.

Vulnerability: All random.random() draws are printed (player + dealer).
  624 consecutive floats (2 MT twist cycles) uniquely determine MT19937 state.

Attack:
  Phase 1 (learn): Play threshold-0.57 strategy (~42.5% win), collect 624
    floats. Expected ~181 rounds, ~77 wins.
  Phase 2 (crack): Z3 recovers MT state from last 624 floats. O(1s).
  Phase 3 (DP): Graph DP over known stream finds optimal hit/stand sequence.
    With perfect future knowledge, achieves ~827/1337 wins deterministically.
    Success probability ~80% per attempt.
"""

import socket, re, random
from z3 import *

HOST = "archive.cryptohack.org"
PORT = 59737

TOTAL_ROUNDS = 1337
WIN_THRESHOLD = 800
THRESHOLD = 0.57055652829519647683

# ── Z3 MT19937 state recovery ───────────────────────────────────────────────

def mtcrack_floats(arr):
    """Recover MT state from exactly 624 consecutive random.random() outputs.
    Returns a Random object synced to the position just after arr[-1]."""
    MT = [BitVec(f'm{i}', 32) for i in range(624)]
    s = Solver()

    def cache(x):
        tmp = Const(f'c{len(s.assertions())}', x.sort())
        s.add(tmp == x)
        return tmp

    def tamper(y):
        y ^= LShR(y, 11)
        y = cache(y ^ (y << 7) & 0x9D2C5680)
        y ^= cache((y << 15) & 0xEFC60000)
        return y ^ LShR(y, 18)

    def getnext():
        x = Concat(Extract(31, 31, MT[0]), Extract(30, 0, MT[1]))
        y = If(x & 1 == 0, BitVecVal(0, 32), BitVecVal(0x9908B0DF, 32))
        MT.append(MT[397] ^ LShR(x, 1) ^ y)
        return tamper(MT.pop(0))

    def getrandbits(n):
        return Extract(31, 32 - n, getnext())

    s.add([Concat(getrandbits(27), getrandbits(26)) == int(f * (1 << 53))
           for f in arr])

    print(f"[Z3] solving with 624 floats...", end='', flush=True)
    assert s.check() == sat, "Z3 unsat"
    print(" sat", flush=True)

    state = [s.model().eval(x).as_long() for x in MT]
    r = random.Random()
    r.setstate((3, tuple(state + [0]), None))
    return r

# ── Graph DP ────────────────────────────────────────────────────────────────

def run_dp(arr, r1wins, r1rounds):
    """Find optimal hit/stand sequence over the known draw stream.
    arr[0] = first card of current unfinished round.
    Returns (max_wins, path_tuple) or (None, None) if < WIN_THRESHOLD."""

    def how_many(threshold, offset):
        total = 0.0
        while total <= threshold:
            if offset >= len(arr):
                return False, offset
            total += arr[offset]
            offset += 1
        return total >= 1.0, offset

    def get_edges(offset):
        total = arr[offset]
        while total < 1.0:
            win, dst = how_many(total, offset + 1)
            yield (offset, 1), (win, dst)
            offset += 1
            if offset >= len(arr):
                break
            total += arr[offset]
        yield (offset, 0), (False, offset + 1)

    def choose(old, new):
        if old is None:
            return new
        return old if (old[0], -old[1]) >= (new[0], -new[1]) else new

    print("[DP] computing optimal path...", flush=True)
    leaf = None
    dic = {0: (r1wins, r1rounds, (b'', None))}
    while dic:
        i = min(dic.keys())
        wins, rounds, parent = dic.pop(i)
        for code, (win, dst) in get_edges(i):
            code_bin = b'\n' * (code[0] - i) + b's\n' * code[1]
            next_state = (wins + int(win), rounds + 1, (code_bin, parent))
            if rounds + 1 == TOTAL_ROUNDS:
                leaf = choose(leaf, next_state)
            else:
                dic[dst] = choose(dic.get(dst), next_state)

    if leaf is None or leaf[0] < WIN_THRESHOLD:
        print(f"[!] Best path = {leaf[0] if leaf else 0} wins < {WIN_THRESHOLD}. Retry.")
        return None, None

    print(f"[+] Found path: {leaf[0]}/{TOTAL_ROUNDS} wins achievable!", flush=True)
    return leaf[0], leaf[2]

# ── Connection ───────────────────────────────────────────────────────────────

class Conn:
    def __init__(self, host, port):
        self.s = socket.socket()
        self.s.connect((host, port))
        self.buf = b''

    def _fill(self):
        chunk = self.s.recv(4096)
        if chunk:
            self.buf += chunk

    def read_until(self, pat):
        bp = pat.encode() if isinstance(pat, str) else pat
        while bp not in self.buf:
            self._fill()
        i = self.buf.index(bp)
        out = self.buf[:i + len(bp)].decode(errors='replace')
        self.buf = self.buf[i + len(bp):]
        return out

    def sendln(self, m):
        self.s.sendall((m + '\n').encode())

    def send_raw(self, data):
        self.s.sendall(data)

    def recv_all_text(self, timeout=30):
        import time
        self.s.settimeout(timeout)
        try:
            while True:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
        except Exception:
            pass
        return self.buf.decode(errors='replace')

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"Connecting to {HOST}:{PORT}...", flush=True)
    conn = Conn(HOST, PORT)

    draws = []
    r1rounds = 0
    r1wins = 0

    def draw_one():
        conn.read_until('draw a [')
        s = conn.read_until(']')
        v = float(s[:-1])
        draws.append(v)
        return v

    # Phase 1: collect 624+ floats with threshold strategy
    while True:
        total = draw_one()

        if len(draws) >= 624:
            break  # server waiting for hit/stand on this first card

        while total < THRESHOLD:
            conn.read_until('? ')
            conn.sendln('h')
            total += draw_one()

        r1rounds += 1
        if total < 1.0:
            conn.read_until('? ')
            conn.sendln('s')

        # Consume rest of round; capture dealer draws; stop at next "Round"
        chunk = conn.read_until('Round')
        for m in re.finditer(r'\[([0-9.eE+\-]+)\]', chunk):
            draws.append(float(m.group(1)))
        if total < 1.0 and 'You win' in chunk:
            r1wins += 1

        conn.read_until('\n')  # consume "N:\n"

        if r1rounds % 20 == 0:
            print(f"  round {r1rounds}: {r1wins} wins, {len(draws)} draws", flush=True)

    print(f"Phase 1 done: {r1rounds} rounds, {r1wins} wins, {len(draws)} floats collected")

    # Phase 2: crack MT state from last 624 floats
    rng = mtcrack_floats(draws[-624:])

    # Build future array: arr[0] = draws[-1] (first card of current round, already drawn)
    arr = draws[-1:] + [rng.random() for _ in range(10000)]

    # Phase 3: graph DP
    max_wins, path = run_dp(arr, r1wins, r1rounds)
    if path is None:
        conn.s.close()
        return False

    # Reconstruct command sequence (path is a linked list in reverse order)
    def get_codes(path_tuple):
        code, parent = path_tuple
        while parent is not None:
            yield code
            code, parent = parent

    commands = b''.join(list(get_codes(path))[::-1])
    print(f"[+] Sending {len(commands)} bytes of commands...", flush=True)
    conn.send_raw(commands)

    # Read output until flag
    output = conn.read_until('flag: ')
    flag_line = conn.read_until('\n')
    print(f"\nFLAG: {flag_line.strip()}", flush=True)

    conn.s.close()
    return True


if __name__ == '__main__':
    import sys
    for attempt in range(5):
        print(f"\n=== Attempt {attempt + 1}/5 ===")
        try:
            if main():
                sys.exit(0)
        except Exception as e:
            print(f"Error: {e}", flush=True)
    print("Failed after 5 attempts.")
