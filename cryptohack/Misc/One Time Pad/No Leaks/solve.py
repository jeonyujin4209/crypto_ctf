"""
No Leaks (50pts) — OTP with rejection sampling reveals the flag

Each request returns `ct[i] = flag[i] ^ otp[i]` where otp is 20 random bytes,
BUT the server asserts `ct[i] != flag[i]` for every position, i.e. rejects any
request where otp[i] == 0 for some i. So the surviving distribution has
otp[i] uniform in 1..255.

Consequence: for each byte position i, ct[i] can take any value EXCEPT
flag[i]. If we collect enough samples, the byte that NEVER appears at
position i IS the flag byte.

We run multiple concurrent socket connections in threads to speed up
sample collection (~4 req/s per connection, so 10 threads ≈ 40 req/s).
"""
import base64
import json
import socket
import threading
import time

HOST = "socket.cryptohack.org"
PORT = 13370

SEEN = [set() for _ in range(20)]
LOCK = threading.Lock()
DONE = threading.Event()
COUNT = [0]


def recv_until(sock, end=b"\n", max_wait=5.0):
    sock.settimeout(max_wait)
    buf = b""
    while not buf.endswith(end):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def worker():
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        recv_until(sock)  # greeting
    except Exception as e:
        print(f"[!] connect failed: {e}")
        return
    try:
        while not DONE.is_set():
            try:
                sock.send((json.dumps({"msg": "request"}) + "\n").encode())
                line = recv_until(sock)
                if not line:
                    return
                j = json.loads(line.decode())
                ct_b64 = j.get("ciphertext")
                if ct_b64 is None:
                    continue
                ct = base64.b64decode(ct_b64)
                with LOCK:
                    for k, b in enumerate(ct):
                        SEEN[k].add(b)
                    COUNT[0] += 1
                    if all(len(s) == 255 for s in SEEN):
                        DONE.set()
                        return
            except Exception:
                return
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    N_THREADS = 20
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(N_THREADS)]
    t0 = time.time()
    for t in threads:
        t.start()

    while not DONE.is_set():
        time.sleep(5)
        with LOCK:
            mins = [256 - len(s) for s in SEEN]
            print(f"  [{COUNT[0]}] t={time.time()-t0:.1f}s  max_missing={max(mins)}  min_missing={min(mins)}")
        if time.time() - t0 > 600:
            print("[!] timed out")
            DONE.set()
            break

    for t in threads:
        t.join(timeout=2)

    flag = bytearray(20)
    for k, s in enumerate(SEEN):
        missing = set(range(256)) - s
        if len(missing) == 1:
            flag[k] = next(iter(missing))
        else:
            print(f"[!] position {k}: {len(missing)} candidates: {sorted(missing)}")
            flag[k] = ord("?")
    print(f"FLAG: {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
