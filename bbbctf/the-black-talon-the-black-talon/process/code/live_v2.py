"""Live attack v2: Drive recommittees aggressively, try to be selected as new user.

Strategy:
1. Connect, get committee info.
2. Wait for natural Propose (or 1 bot quit).
3. NUC + NUR ourselves.
4. After all NURs, compute r = XOR(valid NURs). If active_users[r%len] == us → wait for Begin & observe.
   Else → send Abort + immediately re-Propose for new attempt.
5. When we're chosen, collect N DMs at our positions, BR samples, PR.
6. Compute f'(our_keys) and aggregate across multiple recommittees.
7. If we get enough f^(k) evaluations across multiple polys, solve for secret.
"""
import ssl, socket, time, sys, threading, queue, re, subprocess, random
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
import proto as P

HOST = "the-black-talon.ctfwithbirds.com"
PORT = 1337
TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJiYmItYXBpIiwiYXVkIjoidGhlLWJsYWNrLXRhbG9uIiwiZXhwIjoxNzgwMTgwOTQ2LCJzdWIiOiIxOTQiLCJnZW4iOjAsImlhdCI6MTc3OTU3NjE0Nn0.v0fQdtKRzOCPOHLxc9c077yzTYbB_BiZ3fAJs1iglDaAhheGW10LVwfDL0l2sHUJ9V_BPugXv_2iss5R13tYDg"
POW_SCRIPT = r"C:\Users\UserK\AppData\Local\Temp\bbb_pow.py"
ANSI = re.compile(r'\x1b\[[0-9;]*m')


class Conn:
    def __init__(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((HOST, PORT))
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
        self.s.settimeout(0.1)
        self.buf = b""; self.q = queue.Queue(); self.all = []
        self.dead = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self.dead:
            try:
                d = self.s.recv(65536)
                if not d: self.dead = True; return
                self.buf += d
                while b"\n" in self.buf:
                    ln, self.buf = self.buf.split(b"\n", 1)
                    s = ln.decode("utf-8", "replace")
                    self.all.append((time.time(), s))
                    self.q.put(s)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except OSError:
                self.dead = True; return

    def send(self, line):
        assert "\n" not in line
        self.s.sendall((line + "\n").encode())

    def recv(self, timeout=0.5):
        try: return self.q.get(timeout=timeout)
        except queue.Empty: return None

    def close(self):
        self.dead = True
        try: self.s.close()
        except: pass


def msgfrom(line):
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    return m.groups() if m else None


def solve_pow(chal):
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal],
                       capture_output=True, text=True, timeout=300)
    return r.stdout.strip()


def main():
    c = Conn()
    time.sleep(0.5); c.send(TOKEN)
    pow_chal = None
    end = time.time() + 10
    while time.time() < end and not pow_chal:
        ln = c.recv(0.3)
        if ln and "a2id.v2." in ln:
            for tok in ln.split():
                if tok.startswith("a2id."):
                    pow_chal = tok.strip(",.")
                    break
    print(f"[+] PoW: {pow_chal}")
    sol = solve_pow(pow_chal); c.send(sol)
    print(f"[+] PoW solved")

    # Read setup
    me = saloon = sheriff_name = None; cm = sh = None
    end = time.time() + 30
    while time.time() < end and not (me and saloon and cm and sh):
        ln = c.recv(0.5)
        if ln is None: continue
        clean = ANSI.sub('', ln)
        m = re.search(r'saloon="([^"]+)"', clean)
        if m: saloon = m.group(1)
        m = re.search(r'protagonist="([^"]+)"', clean)
        if m: me = m.group(1); print(f"[+] me={me}")
        m = re.search(r'sheriff="([^"]+)"', clean)
        if m: sheriff_name = m.group(1)
        pm = msgfrom(ln)
        if not pm: continue
        ch, frm, msg = pm
        if msg.startswith("COMMITMENTS"):
            cm = P.parse_commitments(msg); cm["sheriff"] = frm
            print(f"[+] committee={cm['users']}")
        elif msg.startswith("SHARE "):
            sh = P.parse_share(msg)
            print(f"[+] our SHARE key={sh['key']}")
    if not (cm and sh): print("[-] setup fail"); return

    ident = cm['ident']; q = cm['q']; g = cm['g']; p = 2*q+1

    # State machine
    recomm_log = []
    succeeded = []  # list of (nonce, n_dm_collected, br_samples, t_val)
    cur = {"nonce": None, "commits": {}, "nurs": {}, "my_s": None, "my_nuc_sent": False,
           "my_nur_sent": False, "begin_seen": None, "ngs_to_me": [],
           "br": {}, "pr_t": None, "want_chosen": False}

    def reset():
        cur["nonce"] = None; cur["commits"] = {}; cur["nurs"] = {}
        cur["my_s"] = None; cur["my_nuc_sent"] = False
        cur["my_nur_sent"] = False; cur["begin_seen"] = None
        cur["ngs_to_me"] = []; cur["br"] = {}; cur["pr_t"] = None

    def get_active():
        c.send(f"PEEK {saloon}")
        t0 = time.time()
        while time.time() - t0 < 1:
            ln = c.recv(0.1)
            if ln is None: continue
            if ln.startswith("USERS "):
                return ln.split(" ", 1)[1].split(" ")
        return None

    def send_propose(nonce):
        c.send(f"MSG {saloon} RECOMM {ident} {nonce} PROPOSE")
        for _ in range(5):
            a = c.recv(0.1)
            if a == "ACK": break

    def send_nuc(nonce, commit):
        c.send(f"MSG {saloon} RECOMM {ident} {nonce} NUC {P.b36(commit)}")
        for _ in range(5):
            a = c.recv(0.1)
            if a == "ACK": break

    def send_nur(nonce, s):
        c.send(f"MSG {saloon} RECOMM {ident} {nonce} NUR {s}")
        for _ in range(5):
            a = c.recv(0.1)
            if a == "ACK": break

    def send_abort(nonce):
        c.send(f"MSG {saloon} RECOMM {ident} {nonce} JACCUSE attack")
        for _ in range(5):
            a = c.recv(0.1)
            if a == "ACK": break

    last_propose_t = 0
    propose_cooldown = 0.5
    PHASE = "WAIT_PROPOSE"
    phase_start = time.time()
    chosen_count = 0
    SESSION_END = time.time() + 250

    while time.time() < SESSION_END and not c.dead:
        ln = c.recv(0.2)
        if ln is None:
            # Idle. Possibly drive next attempt.
            if PHASE == "WAIT_PROPOSE" and time.time() - last_propose_t > propose_cooldown:
                # Send a Propose
                nonce = random.randint(0, 2**32 - 1)
                send_propose(nonce)
                last_propose_t = time.time()
                propose_cooldown = max(1.0, propose_cooldown * 0.9)
            continue

        pm = msgfrom(ln)
        if not pm: continue
        ch, frm, msg = pm
        if msg.startswith("RELEASED"):
            print(f"!! RELEASED to us: {msg[:200]}")
            continue
        if "RECOMM" not in msg: continue
        parts = msg.split(" ", 4)
        if len(parts) < 4: continue
        _, mid, nonce_s, sub = parts[:4]
        rest = parts[4] if len(parts) > 4 else ""
        if mid != ident: continue
        nonce = int(nonce_s)

        if sub == "PROPOSE":
            if cur["nonce"] is None:
                reset()
                cur["nonce"] = nonce
                # Immediately NUC.
                cur["my_s"] = random.randint(0, (1<<64)-1)
                commit = pow(g, cur["my_s"], q)
                send_nuc(nonce, commit)
                cur["my_nuc_sent"] = True
                PHASE = "NUR_WAIT"
                print(f"\n[propose {nonce}] we NUC'd s={cur['my_s']}")

        elif sub == "NUC":
            if cur["nonce"] == nonce:
                try:
                    commit = P.from_b36(rest.strip())
                    cur["commits"][frm] = commit
                except Exception: pass

        elif sub == "NUR":
            if cur["nonce"] == nonce:
                try:
                    ps = int(rest.strip())
                    cur["nurs"][frm] = ps
                except Exception: pass
                num_nurs = len(cur["nurs"])
                if num_nurs >= 5 and not cur["my_nur_sent"]:
                    send_nur(nonce, cur["my_s"])
                    cur["my_nur_sent"] = True
                    # Wait briefly for our NUR to land.
                    time.sleep(0.3)
                    # Compute predicted user
                    active = get_active()
                    if active and me in active:
                        # XOR of valid NURs + our NUR
                        rs = list(cur["nurs"].values()) + [cur["my_s"]]
                        r = 0
                        for v in rs: r ^= v
                        idx = r % len(active)
                        predicted = active[idx]
                        print(f"  -> {num_nurs+1} NURs, predicted user={predicted}, we={me}")
                        if predicted == me:
                            chosen_count += 1
                            print(f"  *** PREDICTED TO BE CHOSEN ({chosen_count})! Waiting for Begin/NGS ***")
                            PHASE = "OBSERVE_BEGIN"
                        else:
                            # Abort fast, try again
                            send_abort(nonce)
                            reset()
                            PHASE = "WAIT_PROPOSE"
                            last_propose_t = time.time()
                            propose_cooldown = 0.5

        elif sub == "BEGIN":
            if cur["nonce"] == nonce:
                bp = rest.split(" ", 4)
                if len(bp) >= 1:
                    cur["begin_seen"] = bp[0]
                    if bp[0] == me:
                        print(f"  *** Begin confirms user={me}! ***")
                    else:
                        print(f"  Begin user={bp[0]} (not us)")

        elif sub == "NGS":
            # NGS rest = "from_key key value R|N"
            ps = rest.split(" ")
            if len(ps) >= 4 and ch == "@":  # DM to us
                fk = int(ps[0]); k = int(ps[1])
                v = P.from_b36(ps[2]); is_n = ps[3] == "N"
                cur["ngs_to_me"].append((frm, fk, k, v, is_n))

        elif sub == "BR":
            ps = rest.split(" ", 1)
            if len(ps) >= 2:
                k = int(ps[0]); v = P.from_b36(ps[1])
                cur["br"][k] = (frm, v)

        elif sub == "PR":
            if cur["nonce"] == nonce:
                cur["pr_t"] = P.from_b36(rest.strip())
                print(f"  PR seen, t={hex(cur['pr_t'])[:60]}...")
                # Process and save
                ngs_n = [x for x in cur["ngs_to_me"] if x[4]]  # is_n
                print(f"  NGS to us: {len(cur['ngs_to_me'])} (N: {len(ngs_n)}, R: {len(cur['ngs_to_me']) - len(ngs_n)})")
                print(f"  BR samples: {len(cur['br'])}")
                succeeded.append({"nonce": nonce, "ngs_to_me": list(cur["ngs_to_me"]),
                                  "br": dict(cur["br"]), "t": cur["pr_t"]})
                reset()
                PHASE = "WAIT_PROPOSE"
                last_propose_t = time.time()
                propose_cooldown = 0.5

        elif sub == "JACCUSE":
            if cur["nonce"] == nonce:
                reset()
                PHASE = "WAIT_PROPOSE"
                last_propose_t = time.time()

    # Save log
    with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_v2.txt", "w", encoding="utf-8") as f:
        for ts, ln in c.all:
            f.write(f"{ts:.3f}\t{ln}\n")
    print(f"\n[+] Saved {len(c.all)} lines.")
    print(f"[summary] chosen_count={chosen_count}, succeeded={len(succeeded)}")
    for s in succeeded:
        print(f"  ng_to_me={len(s['ngs_to_me'])} br={len(s['br'])} t={hex(s['t'])[:40]}...")

    c.close()


if __name__ == "__main__":
    main()
