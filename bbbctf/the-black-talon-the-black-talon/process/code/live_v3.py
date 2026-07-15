"""Live attack v3: simpler, more diagnostic."""
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
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        raw = socket.create_connection((HOST, PORT))
        self.s = ctx.wrap_socket(raw, server_hostname=HOST); self.s.settimeout(0.1)
        self.buf = b""; self.q = queue.Queue(); self.all=[]; self.dead=False
        threading.Thread(target=self._r, daemon=True).start()
    def _r(self):
        while not self.dead:
            try:
                d = self.s.recv(65536)
                if not d: self.dead=True; return
                self.buf += d
                while b"\n" in self.buf:
                    ln, self.buf = self.buf.split(b"\n", 1)
                    s = ln.decode("utf-8", "replace")
                    self.all.append((time.time(), s)); self.q.put(s)
            except (socket.timeout, ssl.SSLWantReadError): continue
            except OSError: self.dead=True; return
    def send(self, line):
        self.s.sendall((line+"\n").encode())
    def recv(self, t=0.5):
        try: return self.q.get(timeout=t)
        except queue.Empty: return None
    def close(self):
        self.dead=True
        try: self.s.close()
        except: pass


def msgfrom(line):
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    return m.groups() if m else None


def solve_pow(chal):
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal], capture_output=True, text=True, timeout=300)
    return r.stdout.strip()


def main():
    c = Conn()
    time.sleep(0.3); c.send(TOKEN)
    pow_chal = None
    for _ in range(50):
        ln = c.recv(0.3)
        if ln and "a2id." in ln:
            for tok in ln.split():
                if tok.startswith("a2id."): pow_chal = tok.strip(",."); break
            if pow_chal: break
    sol = solve_pow(pow_chal); c.send(sol)
    print(f"[+] PoW done at {time.time()}")
    game_start = time.time()

    me = saloon = sh_name = None; cm = sh = None
    for _ in range(60):
        ln = c.recv(0.5)
        if ln is None:
            if me and saloon and cm and sh: break
            continue
        clean = ANSI.sub('', ln)
        for k, pat in [("saloon", r'saloon="([^"]+)"'), ("me", r'protagonist="([^"]+)"'), ("sh_name", r'sheriff="([^"]+)"')]:
            m = re.search(pat, clean)
            if m:
                if k=="saloon": saloon = m.group(1)
                elif k=="me": me = m.group(1)
                else: sh_name = m.group(1)
        pm = msgfrom(ln)
        if pm:
            _, frm, msg = pm
            if msg.startswith("COMMITMENTS"):
                cm = P.parse_commitments(msg); cm["sheriff"] = frm
            elif msg.startswith("SHARE "):
                sh = P.parse_share(msg)
        if me and saloon and cm and sh: break

    print(f"[+] setup done. me={me}, saloon={saloon}, sh={sh_name}")
    print(f"[+] committee={cm['users']}, key={sh['key']}")
    ident = cm['ident']; q = cm['q']; g = cm['g']; p = 2*q+1

    # Strategy: AGGRESSIVELY drive Proposes. Don't wait for ACK.
    # Track state per nonce.
    nonce_state = {}  # nonce -> {commits, nurs, my_s, observed}
    my_proposes_sent = 0
    last_propose = 0
    chosen_count = 0

    # Loop budget: ~230s from game start (leave buffer for nsjail 300s timeout)
    DEADLINE = game_start + 230

    while time.time() < DEADLINE and not c.dead:
        ln = c.recv(0.15)
        now = time.time()
        elapsed = now - game_start

        # Periodically drive Propose
        if now - last_propose > 3.0:
            n = random.randint(1, 2**32-2)
            try:
                c.send(f"MSG {saloon} RECOMM {ident} {n} PROPOSE")
                my_proposes_sent += 1
                if my_proposes_sent <= 3 or my_proposes_sent % 10 == 0:
                    print(f"  [{elapsed:6.1f}s] sent Propose #{my_proposes_sent} (nonce={n})")
                last_propose = now
            except Exception as e:
                print(f"  [{elapsed:6.1f}s] send err: {e}")
                break

        if ln is None: continue
        if ln == "ACK": continue
        if ln.startswith("ERROR "):
            if not ln.startswith("ERROR Already in channel"):
                print(f"  [{elapsed:6.1f}s] ERROR: {ln[:100]}")
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
        try: n = int(nonce_s)
        except: continue

        # Track key events
        if sub == "PROPOSE":
            print(f"  [{elapsed:6.1f}s] PROPOSE from {frm} (nonce={n}) - bot accepted!")
            # New recomm cycle. NUC immediately.
            ps = random.randint(0, (1<<64)-1)
            commit = pow(g, ps, q)
            nonce_state[n] = {"my_s": ps, "commits": {}, "nurs": {},
                              "ngs_to_me": [], "br": {}, "pr_t": None,
                              "begin_user": None, "my_nured": False}
            c.send(f"MSG {saloon} RECOMM {ident} {n} NUC {P.b36(commit)}")
            print(f"    -> we NUC (s={ps})")

        elif sub == "NUR":
            ns = nonce_state.get(n)
            if ns is None: continue
            try: ns["nurs"][frm] = int(rest.strip())
            except: pass
            if len(ns["nurs"]) >= 5 and not ns["my_nured"]:
                ns["my_nured"] = True
                c.send(f"MSG {saloon} RECOMM {ident} {n} NUR {ns['my_s']}")
                print(f"    [{elapsed:6.1f}s] we NUR (nonce={n}, {len(ns['nurs'])} bots NUR'd)")

        elif sub == "BEGIN":
            ns = nonce_state.get(n)
            if ns is None: continue
            bp = rest.split(" ", 4)
            ns["begin_user"] = bp[0] if bp else None
            if bp and bp[0] == me:
                chosen_count += 1
                print(f"    [{elapsed:6.1f}s] *** BEGIN user={me} (chosen #{chosen_count}) nonce={n} ***")
            else:
                print(f"    [{elapsed:6.1f}s] begin user={bp[0] if bp else '?'} (not us)")

        elif sub == "NGS":
            ns = nonce_state.get(n)
            if ns is None: continue
            ps = rest.split(" ")
            if len(ps) >= 4 and ch == "@":
                try:
                    fk = int(ps[0]); k = int(ps[1]); v = P.from_b36(ps[2]); is_n = (ps[3] == "N")
                    ns["ngs_to_me"].append((frm, fk, k, v, is_n))
                except Exception as e: pass

        elif sub == "BR":
            ns = nonce_state.get(n)
            if ns is None: continue
            ps = rest.split(" ", 1)
            if len(ps) >= 2:
                try: ns["br"][int(ps[0])] = (frm, P.from_b36(ps[1]))
                except: pass

        elif sub == "PR":
            ns = nonce_state.get(n)
            if ns is None: continue
            try:
                t_val = P.from_b36(rest.strip())
                ns["pr_t"] = t_val
                print(f"    [{elapsed:6.1f}s] PR (nonce={n}) t={hex(t_val)[:40]}... ngs={len(ns['ngs_to_me'])} br={len(ns['br'])}")
            except: pass

    # Save
    with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_v3.txt", "w", encoding="utf-8") as f:
        for ts, ln in c.all:
            f.write(f"{ts:.3f}\t{ln}\n")
    print(f"\n[final] my_proposes={my_proposes_sent}, chosen_count={chosen_count}")
    print(f"[final] cycles tracked: {len(nonce_state)}")
    completed = [n for n,ns in nonce_state.items() if ns["pr_t"] is not None]
    print(f"[final] completed (PR seen): {len(completed)}")
    for n in completed[:5]:
        ns = nonce_state[n]
        print(f"  nonce={n}: begin_user={ns['begin_user']}, ngs={len(ns['ngs_to_me'])}, br={len(ns['br'])}")

    # If chosen at least once, save useful data
    chosen = [n for n,ns in nonce_state.items() if ns["begin_user"] == me and ns["pr_t"] is not None]
    if chosen:
        print(f"\n[chosen-as-new-user, completed: {len(chosen)}]")
        for n in chosen:
            ns = nonce_state[n]
            print(f"  nonce={n}: t={hex(ns['pr_t'])[:40]}...")
            for frm, fk, k, v, is_n in ns["ngs_to_me"]:
                print(f"    NGS from {frm} key={k} ({'N' if is_n else 'R'})")

    c.close()


if __name__ == "__main__":
    main()
