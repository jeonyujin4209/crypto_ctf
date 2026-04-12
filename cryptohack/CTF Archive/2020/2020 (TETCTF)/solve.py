#!/usr/bin/env python3
"""
Solver for "2020 (TETCTF)" at archive.cryptohack.org:63222

Challenge:
    nIndices = 2
    indices = [int(input()) for _ in range(nIndices)]
    for i in range(2019):
        r = random.getrandbits(32)
        print(r if i in indices else 'Nope!')
    if int(input()) == random.getrandbits(32):
        print(os.environ["FLAG"])

Strategy:
    We need to predict output[2019] (the 2020th call, 0-indexed).

    MT19937 batching:
        Batch 0:  calls   0 -  623  (positions 0-623 in batch 0 state)
        Batch 1:  calls 624 - 1247  (positions 0-623 in batch 1 state)
        Batch 2:  calls 1248 - 1871 (positions 0-623 in batch 2 state)
        Batch 3:  calls 1872 - 2495 (positions 0-623 in batch 3 state)

    output[2019] = temper(batch3[147])  (since 2019 - 1872 = 147)

    MT recurrence:
        batch3[i] = batch2[(i+397)%624] XOR twist(batch2[i], batch2[(i+1)%624])

    For i=147:
        batch3[147] = batch2[544] XOR twist(batch2[147], batch2[148])

    Where twist(a, b):
        y = (a & 0x80000000) | (b & 0x7fffffff)
        return (y >> 1) XOR (0x9908b0df if y & 1 else 0)

    The twist function ONLY uses the HIGH BIT of 'a' (batch2[147]).
    The high bit of the twist result is ALWAYS 0 (due to >>1).
    The rest depends only on 'b' (batch2[148]).

    If we pick indices 1396 and 1792:
        output[1396] -> untemper -> batch2[148]  (= 1396 - 1248 = 148th position in batch 2)
        output[1792] -> untemper -> batch2[544]  (= 1792 - 1248 = 544th position in batch 2)

    We know batch2[148] and batch2[544] fully.
    The ONLY unknown is the HIGH BIT of batch2[147] (1 bit -> 2 candidates).

    This gives us exactly 2 candidates for output[2019]:
        candidate0: using high_bit(batch2[147]) = 0
        candidate1: using high_bit(batch2[147]) = 1

    We try both. With retry logic, expected ~2 connections to get the flag.
"""

import socket
import sys

HOST = "archive.cryptohack.org"
PORT = 63222

# MT19937 constants
MATRIX_A  = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff

# -----------------------------------------------------------------------
# Temper / Untemper (Python's MT19937 output transformation)
# -----------------------------------------------------------------------
def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7)  & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y & 0xffffffff

def untemper(y):
    # Undo y ^= (y >> 18)
    y ^= (y >> 18)
    # Undo y ^= (y << 15) & 0xefc60000  (only affects bits 30..15, one-round clean)
    y ^= (y << 15) & 0xefc60000
    # Undo y ^= (y << 7) & 0x9d2c5680  (need 4 rounds to recover all bits)
    tmp = y
    tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    y = tmp
    # Undo y ^= (y >> 11)  (need 2 rounds)
    tmp = y
    tmp = y ^ (tmp >> 11)
    tmp = y ^ (tmp >> 11)
    y = tmp
    return y & 0xffffffff

def twist_func(a, b):
    """MT twist operation using high bit of a and low 31 bits of b."""
    y = (a & UPPER_MASK) | (b & LOWER_MASK)
    result = y >> 1
    if y & 1:
        result ^= MATRIX_A
    return result

def compute_candidates(out_1396, out_1792):
    """
    Given revealed outputs at indices 1396 and 1792, compute 2 candidates
    for output[2019] (the 2020th random number).

    Returns list of 2 candidates.
    """
    # Recover batch2 state words
    s2_148 = untemper(out_1396)  # batch2[148]
    s2_544 = untemper(out_1792)  # batch2[544]

    candidates = []
    for high_bit in [0, UPPER_MASK]:
        # Try both options for the high bit of batch2[147]
        twist_val  = twist_func(high_bit, s2_148)
        batch3_147 = s2_544 ^ twist_val
        candidates.append(temper(batch3_147))

    return candidates

# -----------------------------------------------------------------------
# Socket communication
# -----------------------------------------------------------------------
def recvline(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

def sendline(sock, line):
    sock.sendall((str(line) + "\n").encode())

def solve_once(candidate_choice=0):
    """
    Connect to server, pick indices 1396 and 1792, receive the 2 values,
    compute candidates, and submit candidate_choice (0 or 1).

    Returns the server's response (flag line or empty if wrong).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))

    # Read the welcome message
    welcome = recvline(sock)
    print(f"[*] Server: {welcome}")

    # Send index 1 (to get output[1396])
    print(f"[*] Sending index 1396")
    sendline(sock, 1396)

    # Send index 2 (to get output[1792])
    print(f"[*] Sending index 1792")
    sendline(sock, 1792)

    # Read 2019 responses (but only 2 will be numbers, rest are 'Nope!')
    out_1396 = None
    out_1792 = None

    print("[*] Reading 2019 responses...")
    for i in range(2019):
        line = recvline(sock)
        if i == 1396:
            out_1396 = int(line)
            print(f"[*] output[1396] = {out_1396}")
        elif i == 1792:
            out_1792 = int(line)
            print(f"[*] output[1792] = {out_1792}")

    # Compute candidates
    candidates = compute_candidates(out_1396, out_1792)
    print(f"[*] Candidates: {candidates}")

    # Submit the chosen candidate
    guess = candidates[candidate_choice]
    print(f"[*] Submitting candidate[{candidate_choice}] = {guess}")
    sendline(sock, guess)

    # Read result
    result = recvline(sock)
    sock.close()
    return result, candidates

def main():
    max_attempts = 10
    last_candidates = None

    for attempt in range(1, max_attempts + 1):
        print(f"\n{'='*50}")
        print(f"[*] Attempt {attempt}/{max_attempts}")
        print(f"{'='*50}")

        # Alternate between candidate 0 and candidate 1 on retries
        # (but actually each connection has different randomness,
        # so we just always try candidate 0 - 50% success each time)
        # Either candidate is equally likely to be correct.
        candidate_choice = 0

        try:
            result, candidates = solve_once(candidate_choice)
            print(f"[*] Server response: {result}")

            if "CTF{" in result or "flag{" in result or "TETCTF{" in result or "cryptohack{" in result:
                print(f"\n[+] FLAG FOUND: {result}")
                return result

            # Also check if result is non-empty and not 'Nope!' (might be the flag in any format)
            if result and result != "" and "Nope" not in result and "Wrong" not in result:
                print(f"\n[+] Possible flag: {result}")
                return result

            print(f"[-] Wrong answer. Retrying...")

        except Exception as e:
            print(f"[-] Error on attempt {attempt}: {e}")
            import traceback
            traceback.print_exc()

    print("[-] Max attempts reached without finding flag.")
    return None

if __name__ == "__main__":
    flag = main()
    if flag:
        print(f"\nFINAL FLAG: {flag}")
    else:
        sys.exit(1)
