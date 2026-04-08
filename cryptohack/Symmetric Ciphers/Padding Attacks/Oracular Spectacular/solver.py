#!/usr/bin/env python3
"""
Noisy Padding Oracle - Adaptive Top-2 Solver with Retry

Strategy:
- Adaptive Top-2 with LLR scoring per byte (~370 queries/byte)
- Screen all 16 hex candidates, then focus queries on the 2 most likely
- Wrong candidates naturally drop in LLR, correct one surfaces
- Per-byte accuracy ~86%, per-attempt success ~0.5-1%
- Automatic retry until success (~100-600 attempts)

Usage:
  python solver.py              # local test, 5000 trials
  python solver.py local 500    # local test, 500 trials
  python solver.py server 5000  # server solve, max 5000 attempts
"""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math, os, sys, time, json, socket
from collections import Counter

rng = SystemRandom()
HEX_BYTES = [ord(c) for c in '0123456789abcdef']
LOG_P = math.log(0.4 / 0.6)  # ~-0.405, LLR increment for True response


# ═══════════════════ Oracle Implementations ═══════════════════

class LocalOracle:
    def __init__(self):
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return (iv + ct).hex()

    def check_padding(self, ct_hex):
        ct_raw = bytes.fromhex(ct_hex)
        iv, ct = ct_raw[:16], ct_raw[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
            good = True
        except ValueError:
            good = False
        self.query_count += 1
        return good ^ (rng.random() > 0.4)

    def check_message(self, message):
        return "FLAG{local_test}" if message == self.message else None


class ServerOracle:
    def __init__(self, host='socket.cryptohack.org', port=13423):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.s.settimeout(180)
        self.buf = b""
        self.query_count = 0
        self._recv_line()  # banner

    def _recv_line(self):
        while b"\n" not in self.buf:
            data = self.s.recv(8192)
            if not data:
                raise ConnectionError("closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode().strip()

    def _cmd(self, obj):
        self.s.sendall((json.dumps(obj) + "\n").encode())
        return json.loads(self._recv_line())

    def get_ct(self):
        return self._cmd({"option": "encrypt"})["ct"]

    def check_padding(self, ct_hex):
        self.query_count += 1
        if self.query_count % 1000 == 0:
            print(f" q={self.query_count}", end="", flush=True)
        return self._cmd({"option": "unpad", "ct": ct_hex})["result"]

    def check_message(self, message):
        resp = self._cmd({"option": "check", "message": message})
        return resp.get("flag")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# ═══════════════════ Solver Core ═══════════════════

def make_ct(target, inter, pos, pad, cand):
    """Build modified previous-block + target for oracle query."""
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def find_byte(oracle_fn, target, inter, pos, prev_byte, budget):
    """
    Adaptive Top-2 with LLR scoring.

    1. Screen all 16 candidates with 4 queries each (64 queries).
    2. Repeatedly query the 2 candidates with highest LLR (most likely correct).
    3. Wrong candidates in top-2 naturally drop as they accumulate queries,
       allowing the correct candidate to eventually surface.

    Returns (best_candidate, queries_used).
    """
    pad = 16 - pos
    cands = [prev_byte ^ h for h in HEX_BYTES]
    llr = [0.0] * 16
    used = 0

    # Screen: 4 queries per candidate = 64 queries
    for idx in range(16):
        for _ in range(4):
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[idx]))
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    # Adaptive: focus on top-2 by LLR, re-sort each round
    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            r = oracle_fn(make_ct(target, inter, pos, pad, cands[t]))
            llr[t] += LOG_P if r else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return cands[best], used


def solve_attempt(oracle, budget_per_byte=370, verbose=False):
    """
    Single attempt to recover the 32-byte hex message.
    Returns the recovered message string.
    """
    ct_hex = oracle.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    # Attack block 2 (bytes 16-31): target=C2, prev=C1
    inter2 = [0] * 16
    for pos in range(15, -1, -1):
        best, _ = find_byte(oracle.check_padding, c2, inter2, pos, c1[pos],
                            budget_per_byte)
        inter2[pos] = best
    if verbose:
        print(" B2", end="", flush=True)

    # Attack block 1 (bytes 0-15): target=C1, prev=IV
    inter1 = [0] * 16
    for pos in range(15, -1, -1):
        best, _ = find_byte(oracle.check_padding, c1, inter1, pos, iv[pos],
                            budget_per_byte)
        inter1[pos] = best
    if verbose:
        print(" B1", end="", flush=True)

    pt1 = bytes([inter1[i] ^ iv[i] for i in range(16)])
    pt2 = bytes([inter2[i] ^ c1[i] for i in range(16)])
    return (pt1 + pt2).decode('ascii', 'replace')


# ═══════════════════ Runners ═══════════════════

def run_local(n_trials=200):
    """Run solver locally to measure success rate."""
    successes = 0
    wrong_dist = []
    start = time.time()

    for trial in range(1, n_trials + 1):
        oracle = LocalOracle()
        msg = solve_attempt(oracle)

        wrong = sum(1 for i in range(32) if msg[i] != oracle.message[i])
        wrong_dist.append(wrong)
        if wrong == 0:
            successes += 1

        if trial % 20 == 0 or trial == n_trials:
            elapsed = time.time() - start
            avg_w = sum(wrong_dist) / len(wrong_dist)
            rate = 100 * successes / trial
            print(f"[{trial:4d}/{n_trials}]  success={successes}/{trial} "
                  f"({rate:5.1f}%)  avg_wrong={avg_w:.2f}  "
                  f"queries={oracle.query_count}  time={elapsed:.0f}s")

    total_time = time.time() - start
    print(f"\n{'='*60}")
    print(f"FINAL: {successes}/{n_trials} ({100*successes/n_trials:.1f}%)")
    print(f"Wrong byte distribution: {dict(sorted(Counter(wrong_dist).items()))}")
    print(f"Time: {total_time:.1f}s ({total_time/n_trials:.2f}s/trial)")
    print(f"Expected attempts to succeed: {n_trials/max(1,successes):.1f}")
    print(f"{'='*60}")


def run_server(max_attempts=500):
    """Run solver against CryptoHack server with automatic retry (sequential)."""
    start = time.time()

    for attempt in range(1, max_attempts + 1):
        elapsed = time.time() - start
        print(f"Attempt {attempt}/{max_attempts} ({elapsed:.0f}s)", end="", flush=True)

        oracle = None
        try:
            oracle = ServerOracle()
            msg = solve_attempt(oracle, verbose=True)
            flag = oracle.check_message(msg)

            if flag:
                print(f"\n\n{'='*60}")
                print(f"SUCCESS on attempt {attempt}!")
                print(f"FLAG: {flag}")
                print(f"Time: {time.time()-start:.0f}s")
                print(f"{'='*60}")
                with open("flag.txt", "w") as f:
                    f.write(flag + "\n")
                return True
            else:
                print(f"  -> wrong (q={oracle.query_count})")
        except KeyboardInterrupt:
            print("\nAborted by user.")
            return False
        except Exception as e:
            print(f"  -> error: {e}")
        finally:
            if oracle and hasattr(oracle, 'close'):
                oracle.close()

        time.sleep(0.1)

    print(f"\nFailed after {max_attempts} attempts ({time.time()-start:.0f}s)")
    return False


def _worker(worker_id, attempt_counter, lock, found_flag, max_attempts, start):
    """Worker thread for parallel server solving."""
    while not found_flag.is_set():
        with lock:
            num = attempt_counter[0]
            if num > max_attempts:
                return
            attempt_counter[0] += 1

        oracle = None
        try:
            oracle = ServerOracle()
            msg = solve_attempt(oracle)
            flag = oracle.check_message(msg)

            elapsed = time.time() - start
            if flag:
                found_flag.set()
                print(f"\n\n{'='*60}")
                print(f"[W{worker_id}] SUCCESS on attempt {num}!")
                print(f"FLAG: {flag}")
                print(f"Time: {elapsed:.0f}s")
                print(f"{'='*60}")
                with open("flag.txt", "w") as f:
                    f.write(flag + "\n")
                return
            else:
                print(f"[W{worker_id}] attempt {num} -> wrong (q={oracle.query_count}, {elapsed:.0f}s)")
        except Exception as e:
            print(f"[W{worker_id}] attempt {num} -> error: {e}")
        finally:
            if oracle and hasattr(oracle, 'close'):
                oracle.close()


def run_parallel(max_attempts=500, workers=4):
    """Run solver with multiple parallel connections."""
    import threading

    start = time.time()
    attempt_counter = [1]
    lock = threading.Lock()
    found_flag = threading.Event()

    print(f"Starting {workers} parallel workers, max {max_attempts} attempts")
    threads = []
    for i in range(workers):
        t = threading.Thread(target=_worker,
                             args=(i, attempt_counter, lock, found_flag, max_attempts, start))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(0.5)  # stagger connections

    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=1)
    except KeyboardInterrupt:
        print("\nAborted by user. Waiting for workers to stop...")
        found_flag.set()
        for t in threads:
            t.join(timeout=5)

    elapsed = time.time() - start
    total = attempt_counter[0] - 1
    print(f"\nDone. {total} attempts in {elapsed:.0f}s")


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'local'
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4

    if mode == 'server':
        run_server(count)
    elif mode == 'parallel':
        run_parallel(count, workers)
    else:
        run_local(count)
