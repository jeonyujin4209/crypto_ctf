"""Probe the live server: ncat --ssl the-black-talon.ctfwithbirds.com 1337
Goals:
  1. Verify deployment matches local protocol.
  2. Capture COMMITMENTS + SHARE + a recommittee if it occurs.
  3. Compute t and verify g^t == c_0 * prod(r_commits[0]) on real data.
  4. Watch for anything unexpected.
We have ONE 5-min session — be efficient.
"""
import ssl, socket, time, sys, threading, queue, re, json
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
import proto as P

HOST = "the-black-talon.ctfwithbirds.com"
PORT = 1337


class SslConn:
    def __init__(self, host, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port))
        self.s = ctx.wrap_socket(raw, server_hostname=host)
        self.s.settimeout(0.1)
        self.buf = b""
        self.q = queue.Queue()
        self.dead = False
        self.all_lines = []
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self.dead:
            try:
                data = self.s.recv(65536)
                if not data:
                    self.dead = True; return
                self.buf += data
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    s = line.decode("utf-8", "replace")
                    self.all_lines.append((time.time(), s))
                    self.q.put(s)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except OSError:
                self.dead = True; return

    def send(self, line: str):
        assert "\n" not in line
        self.s.sendall((line + "\n").encode())

    def recv(self, timeout=2.0):
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self.dead = True
        try: self.s.close()
        except: pass


def parse_msgfrom(line):
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJiYmItYXBpIiwiYXVkIjoidGhlLWJsYWNrLXRhbG9uIiwiZXhwIjoxNzgwMTgwOTQ2LCJzdWIiOiIxOTQiLCJnZW4iOjAsImlhdCI6MTc3OTU3NjE0Nn0.v0fQdtKRzOCPOHLxc9c077yzTYbB_BiZ3fAJs1iglDaAhheGW10LVwfDL0l2sHUJ9V_BPugXv_2iss5R13tYDg"


def solve_pow(chal):
    import subprocess
    print(f"[+] Solving PoW: {chal}")
    pow_script = r"C:\Users\UserK\AppData\Local\Temp\bbb_pow.py"
    r = subprocess.run(["python", pow_script, "solve", chal],
                       capture_output=True, text=True, timeout=300)
    print(f"  pow stderr: {r.stderr[:200]}")
    sol = r.stdout.strip()
    print(f"  solution: {sol[:60]}...")
    return sol


def main():
    print(f"[+] Connecting to {HOST}:{PORT}")
    c = SslConn(HOST, PORT)
    print(f"[+] Sending team token")
    time.sleep(0.5)
    c.send(TOKEN)

    # Read PoW challenge
    pow_chal = None
    end = time.time() + 10
    while time.time() < end:
        line = c.recv(0.3)
        if line is None:
            continue
        print(f"  RX: {line[:200]}")
        if "a2id.v2." in line:
            # Extract challenge token
            for tok in line.split():
                if tok.startswith("a2id."):
                    pow_chal = tok.strip(",.")
                    break
            if pow_chal:
                break

    if pow_chal:
        sol = solve_pow(pow_chal)
        print(f"[+] Sending PoW solution")
        c.send(sol)
        time.sleep(1)

    # Wait for prompts (we don't need to send CONNECT; orchestrator does it)
    info = {
        "welcomes": [],
        "saloon_msgs": [],
        "commitments": None,
        "share": None,
        "ngc": [],
        "br": [],
        "pr": [],
        "all_recomm": [],
    }
    sheriff_name = None
    saloon_name = None
    my_name = None
    pwd = None
    start = time.time()

    print("[+] Watching for ~250s (give time for sheriff to inject + observe state)...")

    # Receive lines, parse, track state. Stay passive — just observe.
    while time.time() - start < 250 and not c.dead:
        line = c.recv(0.3)
        if line is None:
            continue
        print(f"  RX [{time.time()-start:6.1f}s]: {line[:160]}{'...' if len(line)>160 else ''}")
        # Track key events
        if line.startswith("NEWUSER "):
            pwd = line.split(" ", 1)[1]
            print(f"    [our password] = {pwd}")
        elif line.startswith("JOINED "):
            saloon_name = line.split(" ", 1)[1]
            print(f"    [our saloon] = {saloon_name}")
        elif line.startswith("CONNECTED "):
            my_name = line.split(" ", 1)[1]
            print(f"    [our protagonist name] = {my_name}")
        m = parse_msgfrom(line)
        if m:
            ch, frm, msg = m
            if msg.startswith("COMMITMENTS"):
                info["commitments"] = P.parse_commitments(msg)
                info["commitments"]["sheriff"] = frm
                info["commitments"]["raw_line"] = line
                sheriff_name = frm
                cm = info["commitments"]
                print(f"    [COMMITMENTS] sheriff={frm}, ident={cm['ident']}, q_bits={cm['q'].bit_length()}, users={cm['users']}")
            elif msg.startswith("SHARE "):
                info["share"] = P.parse_share(msg)
                print(f"    [SHARE] our key={info['share']['key']}")
            elif "RECOMM" in msg:
                parts = msg.split(" ", 4)
                sub = parts[3] if len(parts) > 3 else "?"
                info["all_recomm"].append((time.time() - start, frm, msg, sub))
                if sub == "NGC":
                    info["ngc"].append((frm, msg))
                elif sub == "BR":
                    info["br"].append((frm, msg))
                elif sub == "PR":
                    info["pr"].append((frm, msg))
            elif msg.startswith("RELEASED "):
                print(f"    [RELEASED to us!] {msg[:120]}")

    print(f"\n[+] Done observing. Disconnecting.")
    # Save raw lines to disk for later analysis
    with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_lines.txt", "w", encoding="utf-8") as f:
        for ts, line in c.all_lines:
            f.write(f"{ts:.3f}\t{line}\n")
    print(f"[+] Saved {len(c.all_lines)} lines to live_lines.txt")

    # Summary
    print(f"\n[summary]")
    print(f"  our_name={my_name}, saloon={saloon_name}, sheriff={sheriff_name}")
    if info["commitments"]:
        cm = info["commitments"]
        print(f"  ident={cm['ident']}, committee={cm['users']}")
        if my_name:
            print(f"  our_pos_in_committee = {cm['users'].index(my_name)+1 if my_name in cm['users'] else 'NOT IN'}")
    if info["share"]:
        sh = info["share"]; cm = info["commitments"]
        ok = P.is_share_valid(cm['q'], cm['g'], cm['commits'], sh['key'], sh['value'])
        print(f"  share key={sh['key']}, valid={ok}")
    print(f"  Recomm: NGC={len(info['ngc'])} BR={len(info['br'])} PR={len(info['pr'])}")
    print(f"  total recomm msgs: {len(info['all_recomm'])}")

    # If we got BR + PR, verify our math
    if info["br"] and info["pr"] and info["commitments"]:
        cm = info["commitments"]; q = cm['q']; g = cm['g']; p = 2*q+1
        c0 = cm['commits'][0]
        t_val = P.from_b36(info["pr"][0][1].split(" ")[4])
        print(f"\n  t (from PR) = {hex(t_val)[:60]}...")
        if info["ngc"]:
            prod = 1
            for frm, msg in info["ngc"]:
                parts = msg.split(" ")
                r_cs = parts[5].split(",")
                r0 = P.from_b36(r_cs[0])
                prod = (prod * r0) % p
            expected_gt = (c0 * prod) % p
            actual_gt = pow(g, t_val, p)
            match = (expected_gt == actual_gt)
            print(f"  g^t == c_0 * prod(r_commits[0])?  {match}")

    print("[+] Sending GOODBYE")
    try:
        c.send("GOODBYE")
        time.sleep(0.5)
    except: pass
    c.close()


if __name__ == "__main__":
    main()
