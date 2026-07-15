"""Live attack v4: WAIT for natural Propose, then DRIVE.

After getting setup, wait passively for first natural Propose from bots.
Then participate aggressively in subsequent cycles.
"""
import ssl, socket, time, sys, threading, queue, re, subprocess, random
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
import proto as P

HOST = "the-black-talon.ctfwithbirds.com"; PORT = 1337
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
                    s = ln.decode("utf-8", "replace"); self.all.append((time.time(), s)); self.q.put(s)
            except (socket.timeout, ssl.SSLWantReadError): continue
            except OSError: self.dead=True; return
    def send(self, line): self.s.sendall((line+"\n").encode())
    def recv(self, t=0.5):
        try: return self.q.get(timeout=t)
        except queue.Empty: return None


def msgfrom(line):
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    return m.groups() if m else None


def solve_pow(chal):
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal], capture_output=True, text=True, timeout=300)
    return r.stdout.strip()


def main():
    c = Conn(); time.sleep(0.3); c.send(TOKEN)
    pow_chal = None
    for _ in range(50):
        ln = c.recv(0.3)
        if ln and "a2id." in ln:
            for tok in ln.split():
                if tok.startswith("a2id."): pow_chal = tok.strip(",."); break
            if pow_chal: break
    sol = solve_pow(pow_chal); c.send(sol)
    print(f"[+] PoW done")
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
            elif msg.startswith("SHARE "): sh = P.parse_share(msg)
        if me and saloon and cm and sh: break

    print(f"[+] setup: me={me}, saloon={saloon}, sheriff={sh_name}, key={sh['key']}")
    print(f"[+] committee={cm['users']}")
    ident = cm['ident']; q = cm['q']; g = cm['g']; p = 2*q+1

    # Verify our share
    print(f"[+] our share validates: {P.is_share_valid(q, g, cm['commits'], sh['key'], sh['value'])}")

    states = {}  # nonce -> dict
    chosen_completed = []

    def make_state(nonce):
        ps = random.randint(0, (1<<64)-1)
        return {"my_s": ps, "commit": pow(g, ps, q), "nurs": {}, "nuced": False,
                "nured": False, "begin_user": None, "ngs_to_me": [],
                "br": {}, "pr_t": None, "ngc": {}}

    last_active_propose = 0
    DEADLINE = game_start + 240
    natural_seen = False

    while time.time() < DEADLINE and not c.dead:
        ln = c.recv(0.2)
        now = time.time(); elapsed = now - game_start

        # After natural Propose seen, we can drive faster
        if natural_seen and now - last_active_propose > 5:
            n = random.randint(1, 2**32-2)
            c.send(f"MSG {saloon} RECOMM {ident} {n} PROPOSE")
            last_active_propose = now
            # print(f"  [{elapsed:6.1f}s] sent our Propose")

        if ln is None: continue
        if ln == "ACK": continue
        if ln.startswith("ERROR"): continue
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

        if sub == "PROPOSE":
            # This is from a BOT (not us — we don't see our own).
            print(f"  [{elapsed:6.1f}s] PROPOSE from {frm} (nonce={n})")
            natural_seen = True
            if n not in states:
                st = make_state(n); states[n] = st
                c.send(f"MSG {saloon} RECOMM {ident} {n} NUC {P.b36(st['commit'])}")
                print(f"    -> we NUC (s={st['my_s']})")

        elif sub == "NUR":
            st = states.get(n)
            if st is None:
                # Maybe missed PROPOSE — create state on the fly
                if not natural_seen: continue
                st = make_state(n); states[n] = st
                c.send(f"MSG {saloon} RECOMM {ident} {n} NUC {P.b36(st['commit'])}")
            try: st["nurs"][frm] = int(rest.strip())
            except: pass
            if len(st["nurs"]) >= 5 and not st["nured"]:
                st["nured"] = True
                c.send(f"MSG {saloon} RECOMM {ident} {n} NUR {st['my_s']}")
                print(f"    [{elapsed:6.1f}s] we NUR (nonce={n}, {len(st['nurs'])} bots NUR'd)")

        elif sub == "BEGIN":
            st = states.get(n)
            if st is None: continue
            bp = rest.split(" ", 4)
            st["begin_user"] = bp[0] if bp else None
            if bp and bp[0] == me:
                print(f"    [{elapsed:6.1f}s] *** BEGIN user={me} ***")
            else:
                print(f"    [{elapsed:6.1f}s] begin user={bp[0]}")

        elif sub == "NGC":
            st = states.get(n)
            if st is None: continue
            ps = rest.split(" ", 1)
            if len(ps) >= 2:
                k = int(ps[0])
                # ps[1] = "r_commits n_commits"
                rs_ns = ps[1].split(" ", 1)
                if len(rs_ns) == 2:
                    r_cs = [P.from_b36(x) for x in rs_ns[0].split(",")]
                    n_cs = [P.from_b36(x) for x in rs_ns[1].split(",")]
                    st["ngc"][k] = (frm, r_cs, n_cs)

        elif sub == "NGS":
            st = states.get(n)
            if st is None: continue
            ps = rest.split(" ")
            if len(ps) >= 4 and ch == "@":
                try:
                    fk = int(ps[0]); k = int(ps[1]); v = P.from_b36(ps[2]); is_n = (ps[3] == "N")
                    st["ngs_to_me"].append((frm, fk, k, v, is_n))
                except: pass

        elif sub == "BR":
            st = states.get(n)
            if st is None: continue
            ps = rest.split(" ", 1)
            if len(ps) >= 2:
                try: st["br"][int(ps[0])] = (frm, P.from_b36(ps[1]))
                except: pass

        elif sub == "PR":
            st = states.get(n)
            if st is None: continue
            try:
                t_val = P.from_b36(rest.strip())
                st["pr_t"] = t_val
                print(f"    [{elapsed:6.1f}s] PR t={hex(t_val)[:30]}... ngs={len(st['ngs_to_me'])} br={len(st['br'])} begin_user={st.get('begin_user')}")
                if st.get('begin_user') == me:
                    chosen_completed.append(st)
            except: pass

        elif sub == "JACCUSE":
            pass  # ignore

    # Save
    with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_v4.txt", "w", encoding="utf-8") as f:
        for ts, ln in c.all: f.write(f"{ts:.3f}\t{ln}\n")
    print(f"\n[final] states tracked: {len(states)}, chosen_completed: {len(chosen_completed)}")

    # Analyze chosen recommittees
    if chosen_completed:
        print("\n[=== analyzing chosen recommittees ===]")
        for st in chosen_completed:
            t_val = st["pr_t"]
            # Compute g^t mod p, compare to c_0 * prod(r_commits[0]_j)
            prod = 1
            for k, (frm, r_cs, n_cs) in st["ngc"].items():
                prod = (prod * r_cs[0]) % p
            expected = (cm['commits'][0] * prod) % p
            actual = pow(g, t_val, p)
            print(f"  g^t == c_0 * prod(r_commits[0]): {expected == actual}")
            # We received NGS at our positions for N
            ngs_n = [x for x in st["ngs_to_me"] if x[4]]
            ngs_r = [x for x in st["ngs_to_me"] if not x[4]]
            print(f"  ngs_n count: {len(ngs_n)} ngs_r count: {len(ngs_r)}")
            # Group n by from_key (each j) and collect (k, v) evaluations
            from collections import defaultdict
            n_by_j = defaultdict(list)
            for frm, fk, k, v, is_n in ngs_n:
                n_by_j[fk].append((k, v))
            for fk, kvs in sorted(n_by_j.items()):
                ks = sorted(set(k for k,_ in kvs))
                print(f"    j={fk}: evaluations at keys={ks}")
            # Compute our share at each position
            new_share_per_key = {}
            for frm, fk, k, v, is_n in ngs_n:
                if k not in new_share_per_key: new_share_per_key[k] = 0
                new_share_per_key[k] = (new_share_per_key[k] + v) % q
            for k, sn in new_share_per_key.items():
                fp_k = (sn + t_val) % q
                print(f"    f'({k}) = {hex(fp_k)[:30]}...")


if __name__ == "__main__":
    main()
