import json
import socket
import math
import os
import sys

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('socket.cryptohack.org', 13423))
    s.settimeout(60)

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

    # Read banner
    banner = recv_line()
    print(f"Banner: {banner}")

    # Get ciphertext: iv(16) + c1(16) + c2(16) = 48 bytes
    resp = send_cmd({"option": "encrypt"})
    ct_bytes = bytes.fromhex(resp["ct"])
    assert len(ct_bytes) == 48, f"Expected 48 bytes, got {len(ct_bytes)}"

    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    # Each plaintext byte is one of these 16 ASCII values
    hex_chars = [ord(c) for c in '0123456789abcdef']

    total_queries = 0

    def oracle_query(test_ct_hex):
        nonlocal total_queries
        total_queries += 1
        resp = send_cmd({"option": "unpad", "ct": test_ct_hex})
        return resp["result"]

    def recover_block(target_block, prev_block, block_name):
        """Recover intermediate values using noisy padding oracle with Bayesian inference."""
        intermediate = [0] * 16

        for byte_pos in range(15, -1, -1):
            pad_val = 16 - byte_pos  # 1 for last byte, 2 for second-to-last, etc.

            # 16 candidates for intermediate[byte_pos] based on hex constraint
            # plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
            # plaintext must be a hex char, so intermediate = prev_block[byte_pos] ^ hex_char
            candidates = [prev_block[byte_pos] ^ hc for hc in hex_chars]

            n = len(candidates)
            # Log-probabilities (unnormalized, will normalize when needed)
            log_p = [0.0] * n  # uniform prior

            # Oracle probabilities:
            # P(result=True  | valid padding) = 0.4  (oracle lies 60% of the time)
            # P(result=False | valid padding) = 0.6
            # P(result=True  | invalid padding) = 0.6
            # P(result=False | invalid padding) = 0.4
            LV_TRUE = math.log(0.4)   # log P(True|valid)
            LV_FALSE = math.log(0.6)  # log P(False|valid)
            LI_TRUE = math.log(0.6)   # log P(True|invalid)
            LI_FALSE = math.log(0.4)  # log P(False|invalid)

            # Threshold: log-odds > 9.2 means posterior > 0.9999
            THRESHOLD = 9.2
            MAX_Q = 350
            queries_this_byte = 0

            for _ in range(MAX_Q):
                # Normalize log-probabilities
                max_lp = max(log_p)
                log_sum = max_lp + math.log(sum(math.exp(lp - max_lp) for lp in log_p))
                log_p = [lp - log_sum for lp in log_p]

                # Find best candidate and check stopping condition
                best_idx = max(range(n), key=lambda i: log_p[i])
                sum_others = sum(math.exp(log_p[i]) for i in range(n) if i != best_idx)
                if sum_others > 0:
                    log_odds = log_p[best_idx] - math.log(sum_others)
                else:
                    log_odds = float('inf')

                if log_odds >= THRESHOLD:
                    break

                # Build test ciphertext
                # Random bytes for unrecovered positions to avoid accidental multi-byte padding
                modifier = bytearray(os.urandom(16))
                # Set already-recovered bytes for correct padding
                for k in range(byte_pos + 1, 16):
                    modifier[k] = intermediate[k] ^ pad_val
                # Set the byte we're testing
                modifier[byte_pos] = candidates[best_idx] ^ pad_val

                test_ct = (bytes(modifier) + bytes(target_block)).hex()
                result = oracle_query(test_ct)
                queries_this_byte += 1

                # Bayesian update
                if result:  # True
                    log_p[best_idx] += LV_TRUE
                    for i in range(n):
                        if i != best_idx:
                            log_p[i] += LI_TRUE
                else:  # False
                    log_p[best_idx] += LV_FALSE
                    for i in range(n):
                        if i != best_idx:
                            log_p[i] += LI_FALSE

            # Final decision
            max_lp = max(log_p)
            log_sum = max_lp + math.log(sum(math.exp(lp - max_lp) for lp in log_p))
            log_p = [lp - log_sum for lp in log_p]
            best_idx = max(range(n), key=lambda i: log_p[i])

            intermediate[byte_pos] = candidates[best_idx]
            pt_byte = intermediate[byte_pos] ^ prev_block[byte_pos]
            prob = math.exp(log_p[best_idx])
            print(f"  {block_name}[{byte_pos:2d}] = '{chr(pt_byte)}' (prob={prob:.4f}, q={queries_this_byte}, total={total_queries})")
            sys.stdout.flush()

        return intermediate

    print("=== Recovering block 2 (bytes 17-32) ===")
    inter2 = recover_block(c2, c1, "B2")
    pt2 = bytes([inter2[i] ^ c1[i] for i in range(16)])
    print(f"Block 2: {pt2.decode('ascii', errors='replace')}")

    print(f"\n=== Recovering block 1 (bytes 1-16) ===")
    inter1 = recover_block(c1, iv, "B1")
    pt1 = bytes([inter1[i] ^ iv[i] for i in range(16)])
    print(f"Block 1: {pt1.decode('ascii', errors='replace')}")

    message = (pt1 + pt2).decode('ascii', errors='replace')
    print(f"\nRecovered message: {message}")
    print(f"Total queries used: {total_queries} / 12000")

    # Verify hex
    all_hex = all(c in '0123456789abcdef' for c in message)
    print(f"Valid hex string: {all_hex}")

    if not all_hex:
        print("WARNING: Message contains non-hex characters!")

    # Submit
    resp = send_cmd({"option": "check", "message": message})
    print(f"\nServer response: {resp}")

    s.close()
    return resp

if __name__ == "__main__":
    solve()
