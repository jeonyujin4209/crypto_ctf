"""
Server attack script for no-brainrot-allowed.

Usage: python server_attack.py
Connects to challs.umdctf.io:32767, retrieves ct, runs solver.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solver import find_query, A_TOP, B_TOP
from intersect import intersect_with_S
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time

# To use locally without pwntools:
# from pwn import remote, context  # uncomment if pwntools available

N = 89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703
E = 65537
PREFIX = b"UMDCTF{"
SUFFIX = 0x7d
K = 103  # content length guess; from cluster analysis


class ServerOracle:
    """Oracle that talks to remote server. Maintains the connection."""
    
    def __init__(self, host='challs.umdctf.io', port=32767):
        from pwn import remote, context
        context.log_level = 'error'
        self.r = remote(host, port, timeout=15)
        self.queries = 0
        # consume banner and get ct
        data = b''
        while b'Your messages:' not in data:
            chunk = self.r.recv(timeout=10)
            if not chunk: raise RuntimeError("connection closed")
            data += chunk
        for line in data.decode(errors='ignore').splitlines():
            if line.startswith('Your flag:'):
                self.ct = int(line.split()[-1])
                break
        else:
            raise RuntimeError(f"no ct found in: {data!r}")
    
    def query(self, c):
        """Single query: returns True iff brainrot detected."""
        return self.batch([c])[0]
    
    def batch(self, cs):
        """Batched query, up to 25 at a time."""
        results = []
        BATCH_MAX = 25
        for i in range(0, len(cs), BATCH_MAX):
            chunk = cs[i:i+BATCH_MAX]
            msg = ','.join(str(c) for c in chunk).encode()
            self.r.sendline(msg)
            self.queries += len(chunk)
            out = b''
            deadline = time.time() + 60
            while b'Your messages:' not in out and time.time() < deadline:
                got = self.r.recv(timeout=10)
                if not got: break
                out += got
            text = out.decode(errors='ignore')
            idx = text.find('Your messages:')
            if idx >= 0:
                text = text[:idx]
            chunk_results = []
            for piece in text.split('\n\n'):
                piece = piece.strip()
                if not piece: continue
                chunk_results.append('BRAINROT' in piece)
            if len(chunk_results) != len(chunk):
                print(f"WARN: sent {len(chunk)} got {len(chunk_results)} responses")
                # pad with False if missing
                while len(chunk_results) < len(chunk):
                    chunk_results.append(False)
            results.extend(chunk_results[:len(chunk)])
        return results
    
    def close(self):
        try: self.r.close()
        except: pass


def solve_with_server(oracle, K=K):
    """
    Solve flag using server oracle.
    Single-query-per-step but using batching for the BIG queries (which we don't have here).
    
    For our solver we make one query per step. If the server batches well, this is fine.
    686 queries / 25 per batch = ~28 round trips.
    
    But we send 1 at a time here for clarity. To accelerate: do speculative batching where
    we precompute the next K candidate queries assuming both branches.
    """
    n = N
    e = E
    ct = oracle.ct
    
    flag_len = len(PREFIX) + K + 1
    a = bytes_to_long(PREFIX + b"\x20" * K + bytes([SUFFIX]))
    b = bytes_to_long(PREFIX + b"\x7e" * K + bytes([SUFFIX])) + 1
    print(f"start: width 2^{(b-a).bit_length()-1}")
    
    step = 0
    last_w_log = (b - a).bit_length()
    t0 = time.time()
    
    while b - a > 1:
        step += 1
        if step > 5000: 
            print("max steps")
            break
        res = find_query(a, b, n)
        if res is None:
            print(f"step {step}: no candidate, w 2^{(b-a).bit_length()-1}")
            break
        bal, f, i, hit_lo, hit_hi = res
        c = ct * pow(f, e, n) % n
        is_hit = oracle.query(c)
        if is_hit:
            new_a, new_b = hit_lo, hit_hi
        else:
            if (hit_lo - a) >= (b - hit_hi):
                new_a, new_b = a, hit_lo
            else:
                new_a, new_b = hit_hi, b
        new_a = max(new_a, a); new_b = min(new_b, b)
        if new_a >= new_b: break
        tight = intersect_with_S(new_a, new_b, flag_len, PREFIX, SUFFIX)
        if tight is None: 
            print(f"step {step}: ASCII empty")
            break
        new_a, new_b = tight
        if (new_a, new_b) == (a, b):
            print(f"step {step}: no progress, w 2^{(b-a).bit_length()-1}")
            break
        a, b = new_a, new_b
        cur_w = max(0, (b - a).bit_length())
        if last_w_log - cur_w >= 30 or step % 50 == 0 or cur_w < 30:
            print(f"step {step}: w 2^{cur_w}, q={oracle.queries}, t={time.time()-t0:.1f}s")
            last_w_log = cur_w
    
    if b - a == 1:
        flag = long_to_bytes(a)
        print(f"\n{'='*60}\n>>> FLAG: {flag.decode()} <<<\n{'='*60}")
        return flag
    return None


if __name__ == "__main__":
    print("Connecting to server...")
    oracle = ServerOracle()
    print(f"Got ct (bits: {oracle.ct.bit_length()})")
    try:
        flag = solve_with_server(oracle)
        if flag:
            print(f"\nFINAL FLAG: {flag}")
    finally:
        oracle.close()
