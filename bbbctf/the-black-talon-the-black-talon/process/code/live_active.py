"""Live attack v1: Actively participate in recommittee.
Goals:
- NUC ourselves (so other bots can NUR).
- Engineer Begin's user = deadeye by controlling our NUR (timing-based; probabilistic).
- If user=deadeye, observe 2x evaluations of each n_j (if 1 inactive committee bot exists).
- Compute t, observe BR samples, look for any leak.
"""
import ssl, socket, time, sys, threading, queue, re, subprocess, random, json
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
import proto as P

HOST = "the-black-talon.ctfwithbirds.com"
PORT = 1337
TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJiYmItYXBpIiwiYXVkIjoidGhlLWJsYWNrLXRhbG9uIiwiZXhwIjoxNzgwMTgwOTQ2LCJzdWIiOiIxOTQiLCJnZW4iOjAsImlhdCI6MTc3OTU3NjE0Nn0.v0fQdtKRzOCPOHLxc9c077yzTYbB_BiZ3fAJs1iglDaAhheGW10LVwfDL0l2sHUJ9V_BPugXv_2iss5R13tYDg"
POW_SCRIPT = r"C:\Users\UserK\AppData\Local\Temp\bbb_pow.py"


class Conn:
    def __init__(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((HOST, PORT))
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
        self.s.settimeout(0.1)
        self.buf = b""
        self.q = queue.Queue()
        self.all_lines = []
        self.dead = False
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
    return m.groups() if m else None


def solve_pow(chal):
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal],
                       capture_output=True, text=True, timeout=300)
    return r.stdout.strip()


def main():
    c = Conn()
    time.sleep(0.5)
    c.send(TOKEN)

    # Read PoW challenge
    pow_chal = None
    end = time.time() + 10
    while time.time() < end and not pow_chal:
        line = c.recv(0.3)
        if line is None: continue
        if "a2id.v2." in line:
            for tok in line.split():
                if tok.startswith("a2id."):
                    pow_chal = tok.strip(",.")
                    break
    print(f"[+] PoW: {pow_chal}")
    sol = solve_pow(pow_chal)
    c.send(sol)
    print(f"[+] PoW solved")

    ANSI = re.compile(r'\x1b\[[0-9;]*m')

    # Wait for initial protocol setup
    info = {"cm": None, "sh": None, "saloon": None, "proto": None, "sheriff": None}
    end = time.time() + 30
    while time.time() < end:
        line = c.recv(0.5)
        if line is None: continue
        clean = ANSI.sub('', line)
        # Parse orchestrator info messages
        m = re.search(r'saloon=\"([^\"]+)\"', clean)
        if m: info["saloon"] = m.group(1)
        m = re.search(r'protagonist=\"([^\"]+)\"', clean)
        if m: info["proto"] = m.group(1); print(f"[parsed] protagonist={info['proto']}")
        # Parse messages
        pm = parse_msgfrom(line)
        if not pm: continue
        ch, frm, msg = pm
        if msg.startswith("COMMITMENTS"):
            info["cm"] = P.parse_commitments(msg)
            info["cm"]["sheriff"] = frm
            info["sheriff"] = frm
            print(f"[+] sheriff={frm}, ident={info['cm']['ident']}, users={info['cm']['users']}")
        elif msg.startswith("SHARE "):
            info["sh"] = P.parse_share(msg)
            print(f"[+] our share key={info['sh']['key']}")
        if info["cm"] and info["sh"]: break

    if not (info["cm"] and info["sh"]):
        print("[-] Setup failed"); return

    cm = info["cm"]; sh = info["sh"]
    q = cm["q"]; g = cm["g"]; p = 2*q+1
    me = info["proto"]
    print(f"[+] me={me}, saloon={info['saloon']}, committee={cm['users']}")

    # Plan: wait for natural Propose (100s), then NUC immediately, NUR after seeing 5+ NURs.
    # If r mod len = idx(me), we win. Else abort and retry.

    my_pos_in_committee = cm['users'].index(me)
    print(f"[+] my position in committee = {my_pos_in_committee} (0-indexed)")

    # State for current recommittee
    state = {
        "active_ident": None,
        "active_nonce": None,
        "commits": {},  # idx -> commit
        "nurs": {},  # u64 value (we'll observe broadcasted)
        "my_proposed_share": None,
        "my_commit": None,
        "have_nuced": False,
        "have_nured": False,
        "begin_user": None,
    }

    def reset_state():
        state["active_ident"] = None
        state["active_nonce"] = None
        state["commits"] = {}
        state["nurs"] = {}
        state["my_proposed_share"] = None
        state["my_commit"] = None
        state["have_nuced"] = False
        state["have_nured"] = False
        state["begin_user"] = None

    # Main loop: react to incoming RECOMM messages.
    print(f"[+] Entering main loop (~250s, awaiting recommittee)...")
    end = time.time() + 250
    iter_count = 0
    while time.time() < end and not c.dead:
        iter_count += 1
        line = c.recv(0.3)
        if line is None:
            continue
        pm = parse_msgfrom(line)
        if not pm:
            continue
        ch, frm, msg = pm
        if "RECOMM" not in msg:
            if msg.startswith("RELEASED"):
                print(f"!! RELEASED to us: {msg[:120]}")
            continue
        parts = msg.split(" ", 4)
        if len(parts) < 4: continue
        # parts = [RECOMM, ident, nonce, SUB, rest?]
        ident = parts[1]; nonce = int(parts[2]); sub = parts[3]
        rest = parts[4] if len(parts) > 4 else ""

        if ident != cm['ident']:
            continue
        elapsed = time.time() - (end - 250)
        print(f"  [{elapsed:6.1f}s] {frm}: {sub} (nonce={nonce})")

        if sub == "PROPOSE":
            if state["active_nonce"] != nonce:
                reset_state()
                state["active_ident"] = ident
                state["active_nonce"] = nonce
                print(f"    new Propose accepted, nonce={nonce}")
            # WE NUC immediately. Choose random proposed_share.
            if not state["have_nuced"]:
                ps = random.randint(0, (1<<64)-1)
                state["my_proposed_share"] = ps
                # commit = g^ps mod q
                state["my_commit"] = pow(g, ps, q)
                nuc_msg = f"RECOMM {ident} {nonce} NUC {P.b36(state['my_commit'])}"
                c.send(f"MSG {info['saloon']} {nuc_msg}")
                state["have_nuced"] = True
                print(f"    -> we NUC'd with s={ps}")
                # Drain ACK
                t0 = time.time()
                while time.time() - t0 < 0.5:
                    ack = c.recv(0.1)
                    if ack == "ACK": break

        elif sub == "NUC":
            # rest = "<commit_b36>"
            try:
                commit = P.from_b36(rest.strip())
                idx = cm['users'].index(frm)
                state["commits"][idx] = commit
            except (ValueError, IndexError):
                pass

        elif sub == "NUR":
            # rest = "<proposed_share>"
            try:
                ps = int(rest.strip())
                state["nurs"][frm] = ps
            except (ValueError, IndexError):
                pass
            # If 5+ NURs received (excluding us), send our NUR.
            num_nurs = len(state["nurs"])
            print(f"    {num_nurs} NURs so far")
            if num_nurs >= 5 and not state["have_nured"]:
                # Send our NUR
                nur_msg = f"RECOMM {ident} {nonce} NUR {state['my_proposed_share']}"
                c.send(f"MSG {info['saloon']} {nur_msg}")
                state["have_nured"] = True
                print(f"    -> we NUR'd with s={state['my_proposed_share']}")
                t0 = time.time()
                while time.time() - t0 < 0.5:
                    ack = c.recv(0.1)
                    if ack == "ACK": break

        elif sub == "BEGIN":
            # rest = "user initiator q g old_users"
            bparts = rest.split(" ", 4)
            if len(bparts) >= 5:
                begin_user = bparts[0]
                state["begin_user"] = begin_user
                print(f"    !!! Begin with user={begin_user} (we are {me})")
                if begin_user == me:
                    print(f"    *** WE WERE SELECTED AS NEW USER ***")

        elif sub == "JACCUSE":
            print(f"    [abort] from {frm}: {rest}")
            reset_state()

        elif sub in ("NGC", "BR", "PR"):
            pass  # observe

    # Save all lines
    with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_attack_v1.txt", "w", encoding="utf-8") as f:
        for ts, line in c.all_lines:
            f.write(f"{ts:.3f}\t{line}\n")
    print(f"[+] Saved {len(c.all_lines)} lines.")
    print(f"[summary] commits={len(state['commits'])} nurs={len(state['nurs'])} begin_user={state['begin_user']}")

    c.close()


if __name__ == "__main__":
    main()
