"""
Oracular Spectacular - Noisy Padding Oracle Attack
Algorithm: Adaptive top-2 best-arm identification
Per-byte accuracy: ~85%, per-trial success: ~0.6-0.8%
Retries automatically until success.
"""

import json
import socket
import math
import sys
import os
import time

LOG_P = math.log(0.4 / 0.6)  # ~-0.405
HEX_CHARS = [ord(c) for c in '0123456789abcdef']


def solve_once():
    """Single attempt. Returns (success, flag_or_none)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('socket.cryptohack.org', 13423))
    s.settimeout(120)

    buf = b""

    def recv_line():
        nonlocal buf
        while b"\n" not in buf:
            data = s.recv(4096)
            if not data:
                raise ConnectionError("Connection closed")
            buf += data
        line, buf = buf.split(b"\n", 1)
        return line.decode().strip()

    def send_cmd(cmd):
        s.sendall((json.dumps(cmd) + "\n").encode())
        return json.loads(recv_line())

    try:
        banner = recv_line()

        # Get ciphertext (FREE)
        resp = send_cmd({"option": "encrypt"})
        ct_bytes = bytes.fromhex(resp["ct"])
        iv = list(ct_bytes[:16])
        c1 = list(ct_bytes[16:32])
        c2 = list(ct_bytes[32:48])

        total_q = 0

        def oracle(ct_hex):
            nonlocal total_q
            total_q += 1
            return send_cmd({"option": "unpad", "ct": ct_hex})["result"]

        def make_ct(target, inter, pos, pad, cand):
            m = bytearray(os.urandom(16))
            for k in range(pos + 1, 16):
                m[k] = inter[k] ^ pad
            m[pos] = cand ^ pad
            return (bytes(m) + bytes(target)).hex()

        def find_byte(target, inter, pos, prev_byte, budget):
            pad = 16 - pos
            cands = [prev_byte ^ h for h in HEX_CHARS]
            llr = [0.0] * 16
            used = 0

            # Screen: 2 queries per candidate
            for idx in range(16):
                for _ in range(2):
                    if used >= budget:
                        break
                    r = oracle(make_ct(target, inter, pos, pad, cands[idx]))
                    llr[idx] += LOG_P if r else -LOG_P
                    used += 1

            # Adaptive: focus on top 2, re-sorted each round
            while used < budget:
                sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
                for t in sorted_idx[:2]:
                    if used >= budget:
                        break
                    r = oracle(make_ct(target, inter, pos, pad, cands[t]))
                    llr[t] += LOG_P if r else -LOG_P
                    used += 1

            best = max(range(16), key=lambda i: llr[i])
            return cands[best], used

        def recover_block(target, prev, bytes_after):
            inter = [0] * 16
            for pos in range(15, -1, -1):
                remaining_bytes = pos + 1 + bytes_after
                remaining_q = 11950 - total_q
                budget = min(remaining_q // max(1, remaining_bytes), 400)
                budget = max(budget, 100)
                best, _ = find_byte(target, inter, pos, prev[pos], budget)
                inter[pos] = best
            return inter

        # Recover both blocks
        i2 = recover_block(c2, c1, 16)
        pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])

        i1 = recover_block(c1, iv, 0)
        pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])

        msg = (pt1 + pt2).decode('ascii', 'replace')

        # Submit
        resp = send_cmd({"option": "check", "message": msg})

        if "flag" in resp:
            return True, resp["flag"]
        else:
            return False, None

    finally:
        try:
            s.close()
        except:
            pass


def main():
    max_attempts = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    start_time = time.time()

    for attempt in range(1, max_attempts + 1):
        elapsed = time.time() - start_time
        rate = attempt / elapsed if elapsed > 0 else 0
        print(f"Attempt {attempt}/{max_attempts} (elapsed: {elapsed:.0f}s, "
              f"{rate:.2f} att/s)", end="", flush=True)

        try:
            success, flag = solve_once()
            if success:
                print(f" -> SUCCESS!")
                print(f"\n{'='*60}")
                print(f"FLAG: {flag}")
                print(f"Found on attempt {attempt}")
                print(f"Total time: {time.time()-start_time:.0f}s")
                print(f"{'='*60}")

                # Save flag
                with open("flag.txt", "w") as f:
                    f.write(flag + "\n")
                return
            else:
                print(f" -> wrong")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f" -> error: {e}")

        time.sleep(0.3)

    print(f"\nFailed after {max_attempts} attempts ({time.time()-start_time:.0f}s)")


if __name__ == "__main__":
    main()
