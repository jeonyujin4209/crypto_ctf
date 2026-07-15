"""LIVE attack v5: adapt working local_full_attack to live server.

Adds:
- TLS connection + token auth
- PoW solve
- Read orchestrator output for saloon/me/sheriff names
- After secret recovery, GOODBYE then send guess to orchestrator → flag

The protocol attack itself is identical to local_full_attack.py.
"""
import ssl, socket, time, sys, threading, queue, re, subprocess, random, functools
print = functools.partial(print, flush=True)
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
import proto as P
from collections import defaultdict

HOST = "the-black-talon.ctfwithbirds.com"; PORT = 1337
TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJiYmItYXBpIiwiYXVkIjoidGhlLWJsYWNrLXRhbG9uIiwiZXhwIjoxNzgwMTgwOTQ2LCJzdWIiOiIxOTQiLCJnZW4iOjAsImlhdCI6MTc3OTU3NjE0Nn0.v0fQdtKRzOCPOHLxc9c077yzTYbB_BiZ3fAJs1iglDaAhheGW10LVwfDL0l2sHUJ9V_BPugXv_2iss5R13tYDg"
POW_SCRIPT = r"C:\Users\UserK\AppData\Local\Temp\bbb_pow.py"
ANSI = re.compile(r'\x1b\[[0-9;]*m')


class Conn:
    """TLS-wrapped TCP client matching the local Conn interface."""
    def __init__(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((HOST, PORT))
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
        self.s.settimeout(0.1)
        self.buf = b""
        self.q = queue.Queue()
        self.all = []  # debug log
        self.dead = False
        self.line_filter = None
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self.dead:
            try:
                data = self.s.recv(65536)
                if not data:
                    self.dead = True
                    return
                self.buf += data
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    s = line.decode("utf-8", "replace")
                    self.all.append((time.time(), s))
                    if self.line_filter is None or self.line_filter(s):
                        self.q.put(s)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except OSError:
                self.dead = True
                return

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
        except OSError: pass


def parse_msg(line):
    m = re.match(r"^MSGFROM (\S+) (\S+) (.*)$", line)
    return m.groups() if m else None


def solve_pow(chal):
    r = subprocess.run(["python", POW_SCRIPT, "solve", chal],
                       capture_output=True, text=True, timeout=300)
    return r.stdout.strip()


def peek(c, chan):
    c.send(f"PEEK {chan}")
    end = time.time() + 2
    while time.time() < end:
        r = c.recv(0.1)
        if r and r.startswith("USERS "):
            return r.split(" ", 1)[1].split(" ")
    return None


def drain(c, dur=0.3):
    end = time.time() + dur
    requeued = []
    while time.time() < end:
        ln = c.recv(0.05)
        if ln is None: break
        if ln == "ACK" or ln.startswith("ERROR") or ln.startswith("USERS ") or ln.startswith("CHANNELS"):
            pass
        else:
            if len(requeued) < 500:
                requeued.append(ln)
    for ln in requeued:
        c.q.put(ln)


def main():
    # === Phase 0: Connect + PoW ===
    c = Conn()
    time.sleep(0.3)
    c.send(TOKEN)
    pow_chal = None
    for _ in range(50):
        ln = c.recv(0.3)
        if ln and "a2id." in ln:
            for tok in ln.split():
                if tok.startswith("a2id."):
                    pow_chal = tok.strip(",.")
                    break
            if pow_chal: break
    print(f"[+] PoW challenge: {pow_chal[:40]}...")
    t0 = time.time()
    sol = solve_pow(pow_chal)
    print(f"[+] PoW solved in {time.time()-t0:.1f}s, sending solution")
    c.send(sol)
    game_start = time.time()

    # === Phase 1: Setup — read orchestrator + sheriff Commitments ===
    me = saloon = sh_name = None
    cm = sh = None
    end = time.time() + 30
    while time.time() < end and (not (me and saloon and cm and sh)):
        ln = c.recv(0.5)
        if ln is None: continue
        clean = ANSI.sub('', ln)
        for k, pat in [("saloon", r'saloon="([^"]+)"'),
                       ("me", r'protagonist="([^"]+)"'),
                       ("sh_name", r'sheriff="([^"]+)"')]:
            m = re.search(pat, clean)
            if m:
                if k == "saloon": saloon = m.group(1)
                elif k == "me": me = m.group(1)
                else: sh_name = m.group(1)
        pm = parse_msg(ln)
        if pm:
            _, frm, msg = pm
            if msg.startswith("COMMITMENTS"):
                cm = P.parse_commitments(msg); cm["sheriff"] = frm
            elif msg.startswith("SHARE "):
                sh = P.parse_share(msg)
    if not (me and saloon and cm and sh):
        print(f"[!] setup incomplete: me={me} saloon={saloon} sheriff={sh_name} cm={'OK' if cm else 'NONE'} sh={'OK' if sh else 'NONE'}")
        return

    q = cm["q"]; g = cm["g"]; p = 2*q+1
    sheriff_ident = cm['ident']
    print(f"[+] setup: me={me} saloon={saloon} sheriff={sh_name}")
    print(f"[+] committee={cm['users']}, our_key={sh['key']}")
    print(f"[+] elapsed: {time.time()-game_start:.1f}s, share valid: {P.is_share_valid(q, g, cm['commits'], sh['key'], sh['value'])}")

    # Install filter to drop irrelevant traffic
    def _filter(s):
        if s == "ACK" or s.startswith("ERROR") or s.startswith("USERS ") or s.startswith("CHANNELS"):
            return True
        if not s.startswith("MSGFROM "):
            return True
        return (f"RECOMM {sheriff_ident}" in s or "RECOMM K" in s
                or "COMMITMENTS" in s or "SHARE " in s or "RELEASED " in s)
    c.line_filter = _filter
    drain(c, 1)

    CHAN = saloon
    sheriff_users = list(cm['users'])
    n_my_positions = sheriff_users.count(me)
    dead_set = set()
    collected_evals = []
    chosen_count = 0
    cycle = 0
    MAX_CYCLES = 1500
    CYCLE_DEADLINE = game_start + 265  # tighter, leaves ~25s for GOODBYE + guess (nsjail 300s)
    kill_counter = 0
    kill_needed = False
    recovered_secret = None

    def kill_one_bot(target_name, my_us_in_chan):
        nonlocal kill_counter
        kill_counter += 1
        kill_ident = f"K{kill_counter:08d}"
        forged_users = [target_name] + [my_us_in_chan] * 6 + ["fake_dead_zz"]
        cs_str = ",".join(P.b36(x) for x in [g, 1, 1, 1, 1])
        us_str = ",".join(forged_users)
        c.send(f"MSG {CHAN} COMMITMENTS {kill_ident} {P.b36(q)} {P.b36(g)} {cs_str} {us_str}")
        drain(c, 0.3)
        c.send(f"MSG @{target_name} SHARE {kill_ident} 1 1")
        drain(c, 0.1)
        c.send(f"MSG @{my_us_in_chan} SHARE {kill_ident} 1 1")
        drain(c, 0.5)
        nk = random.randint(1, 2**32-2)
        c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} PROPOSE")
        our_s_list = [random.randint(0, (1<<64)-1) for _ in range(6)]
        for s in our_s_list:
            c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} NUC {P.b36(pow(g, s, q))}")
        target_s = None
        end = time.time() + 5.0
        while time.time() < end:
            if target_s is not None: break
            ln = c.recv(0.15)
            if ln is None: continue
            pm = parse_msg(ln)
            if not pm: continue
            ch, frm, msg = pm
            if frm != target_name: continue
            if not msg.startswith(f"RECOMM {kill_ident} {nk}"): continue
            parts = msg.split(" ", 4)
            if len(parts) >= 5 and parts[3] == "NUR":
                try: target_s = int(parts[4].strip())
                except: pass

        active = None
        for _ in range(5):
            active = peek(c, CHAN)
            if active: break
            time.sleep(0.2)
        if not active:
            return
        target_idx = active.index(target_name) if target_name in active else -1
        us_idx = active.index(my_us_in_chan) if my_us_in_chan in active else -1
        N = len(active)
        chosen_subset = None
        chosen_user = None
        if target_s is not None:
            for bitmask in range(1 << 6):
                if bin(bitmask).count("1") < 4: continue
                our_xor = 0
                for i in range(6):
                    if bitmask & (1 << i): our_xor ^= our_s_list[i]
                r = target_s ^ our_xor
                idx = r % N
                if idx == target_idx:
                    chosen_subset = bitmask; chosen_user = target_name; break
                elif idx == us_idx:
                    chosen_subset = bitmask; chosen_user = my_us_in_chan; break
        if chosen_subset is None:
            chosen_subset = (1 << 6) - 1; chosen_user = my_us_in_chan

        print(f"      [kill {kill_ident}] target_s={'OK' if target_s is not None else 'NONE'} target_idx={target_idx} us_idx={us_idx} N={N} chosen={chosen_user==target_name and 'TARGET' or 'US'}")

        for i in range(6):
            if chosen_subset & (1 << i):
                c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} NUR {our_s_list[i]}")
                drain(c, 0.05)
        bu = ",".join(forged_users)
        c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} BEGIN {chosen_user} {my_us_in_chan} {P.b36(q)} {P.b36(g)} {bu}")
        drain(c, 8.0)

    # Initial kill
    initial_victim = [u for u in cm['users'] if u != me][0]
    print(f"[+] initial kill: {initial_victim}, elapsed: {time.time()-game_start:.1f}s")
    initial_killed = False
    for retry in range(5):
        kill_one_bot(initial_victim, me)
        drain(c, 1.5)
        # Re-peek after extra wait (target's panic propagation can be slow on live)
        for peek_try in range(3):
            after = peek(c, CHAN)
            if after and initial_victim not in after:
                dead_set.add(initial_victim)
                initial_killed = True
                print(f"  -> {initial_victim} dead (active: {len(after)}) after {retry+1} kill attempts")
                break
            time.sleep(0.5)
        if initial_killed: break
        print(f"  -> retry {retry+1}/5")
    if not initial_killed:
        print("[-] initial kill failed; aborting")
        return

    # === Phase 2: R chain ===
    while cycle < MAX_CYCLES and time.time() < CYCLE_DEADLINE and not c.dead and recovered_secret is None:
        cycle += 1
        elapsed = time.time() - game_start
        if cycle <= 10 or cycle % 20 == 0:
            print(f"cycle {cycle} starting, elapsed={elapsed:.1f}s")

        if kill_needed and len(sheriff_users) > 1:
            target = next((u for u in sheriff_users if u != me and u not in dead_set), None)
            if target:
                print(f"  cycle {cycle}: trying to kill {target}")
                kill_one_bot(target, me)
                drain(c, 1.0)
                after = peek(c, CHAN)
                if after and target not in after:
                    dead_set.add(target)
                    print(f"    -> {target} confirmed dead (active count: {len(after)})")
                    kill_needed = False
                else:
                    print(f"    -> {target} STILL ALIVE; retry next cycle")

        nonce = random.randint(1, 2**32 - 2)
        c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} PROPOSE")
        drain(c, 0.3)

        my_s_list = [random.randint(0, (1<<64)-1) for _ in range(n_my_positions)]
        for s in my_s_list:
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} NUC {P.b36(pow(g, s, q))}")
            drain(c, 0.05)

        alive_bot_count = sum(1 for u in sheriff_users if u != me and u not in dead_set)
        nurs = {}
        commits_seen = {}
        end_wait = time.time() + 6.0
        while time.time() < end_wait:
            if len(nurs) >= alive_bot_count: break
            ln = c.recv(0.15)
            if ln is None: continue
            pm = parse_msg(ln)
            if not pm: continue
            _, frm, msg = pm
            if msg.startswith(f"RECOMM {sheriff_ident} {nonce}"):
                parts = msg.split(" ", 4)
                sub = parts[3]
                if sub == "NUR":
                    try: nurs[frm] = int(parts[4].strip())
                    except: pass
                elif sub == "NUC":
                    commits_seen[frm] = parts[4]

        K = len(my_s_list)
        if len(nurs) < alive_bot_count:
            if cycle % 3 == 0:
                print(f"  cycle {cycle}: nurs={len(nurs)}/{alive_bot_count} K={K} - missing bot NURs, skip")
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} JACCUSE abort")
            drain(c, 0.3)
            continue
        if len(nurs) + K < 5:
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} JACCUSE abort")
            drain(c, 0.3)
            continue

        active = peek(c, CHAN)
        if not active or me not in active:
            print(f"[!] WE'RE NOT IN ACTIVE_USERS, something wrong")
            break
        my_idx_in_active = active.index(me)
        N = len(active)

        X = 0
        for v in nurs.values(): X ^= v

        target_subset = None
        min_subset_size = max(0, 5 - len(nurs))
        for bitmask in range(0, 1 << K):
            if bin(bitmask).count("1") < min_subset_size: continue
            our_xor = 0
            for i in range(K):
                if bitmask & (1 << i): our_xor ^= my_s_list[i]
            r = X ^ our_xor
            if r % N == my_idx_in_active:
                target_subset = bitmask
                break

        if target_subset is None:
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} JACCUSE noidx")
            drain(c, 0.3)
            if cycle % 5 == 0:
                print(f"  cycle {cycle}: K={K} N={N} no_match my_idx={my_idx_in_active}")
            continue
        else:
            if cycle % 3 == 0:
                print(f"  cycle {cycle}: K={K} N={N} MATCH subset={bin(target_subset)} my_idx={my_idx_in_active}")

        for i in range(K):
            if target_subset & (1 << i):
                c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} NUR {my_s_list[i]}")
                drain(c, 0.05)
        drain(c, 0.3)

        begin_users = ",".join(sheriff_users)
        begin_msg = f"BEGIN {me} {cm['sheriff']} {P.b36(q)} {P.b36(g)} {begin_users}"
        c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} {begin_msg}")
        drain(c, 0.5)

        my_r_recomm = random.randint(0, q-1)
        r_c0 = pow(g, my_r_recomm, p)
        n_c0 = pow(g, (q - my_r_recomm) % q, p)
        r_commits = [r_c0, 1, 1, 1, 1]
        n_commits = [n_c0, 1, 1, 1, 1]
        ngc_r_str = ",".join(P.b36(x) for x in r_commits)
        ngc_n_str = ",".join(P.b36(x) for x in n_commits)
        for pos in range(len(sheriff_users)):
            if sheriff_users[pos] == me:
                key = pos + 1
                c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} NGC {key} {ngc_r_str} {ngc_n_str}")
                drain(c, 0.05)
        drain(c, 0.3)

        new_users_view = list(sheriff_users) + [me]
        new_users_view = [u for u in new_users_view if u not in dead_set]

        my_r_b36 = P.b36(my_r_recomm)
        q_minus_r = (q - my_r_recomm) % q
        n_val_b36 = P.b36(q_minus_r)
        for pos in range(len(sheriff_users)):
            recipient = sheriff_users[pos]
            if recipient == me: continue
            if recipient in dead_set: continue
            key = pos + 1
            for our_pos_idx, u in enumerate(sheriff_users):
                if u == me:
                    from_key = our_pos_idx + 1
                    c.send(f"MSG @{recipient} RECOMM {sheriff_ident} {nonce} NGS {from_key} {key} {my_r_b36} R")
                    drain(c, 0.02)
        for npos, recipient in enumerate(new_users_view):
            key = npos + 1
            if recipient == me: continue
            for our_pos_idx, u in enumerate(sheriff_users):
                if u == me:
                    from_key = our_pos_idx + 1
                    c.send(f"MSG @{recipient} RECOMM {sheriff_ident} {nonce} NGS {from_key} {key} {n_val_b36} N")
                    drain(c, 0.02)
        drain(c, 0.5)

        begin_user = None
        begin_seen = False
        ngs_to_me = []
        br_seen = {}
        pr_t = None

        end_collect = time.time() + 4
        while time.time() < end_collect:
            ln = c.recv(0.2)
            if ln is None: continue
            pm = parse_msg(ln)
            if not pm: continue
            ch, frm, msg = pm
            if not msg.startswith(f"RECOMM {sheriff_ident} {nonce}"): continue
            parts = msg.split(" ", 4)
            if len(parts) < 5: continue
            sub = parts[3]; rest = parts[4]
            if sub == "NGS" and ch == "@":
                ps = rest.split(" ")
                if len(ps) >= 4:
                    try:
                        fk = int(ps[0]); k = int(ps[1]); v = P.from_b36(ps[2]); is_n = (ps[3] == "N")
                        ngs_to_me.append((frm, fk, k, v, is_n))
                    except: pass
            elif sub == "BR":
                ps = rest.split(" ", 1)
                if len(ps) >= 2:
                    try: br_seen[int(ps[0])] = (frm, P.from_b36(ps[1]))
                    except: pass
            elif sub == "PR":
                try: pr_t = P.from_b36(rest.strip())
                except: pass
            elif sub == "BEGIN":
                bp = rest.split(" ", 4)
                begin_user = bp[0] if bp else None
                begin_seen = True

        end_wait2 = time.time() + 10
        while time.time() < end_wait2:
            ln = c.recv(0.3)
            if ln is None: continue
            pm = parse_msg(ln)
            if not pm: continue
            ch, frm, msg = pm
            if not msg.startswith(f"RECOMM {sheriff_ident} {nonce}"): continue
            parts = msg.split(" ", 4)
            sub = parts[3]; rest = parts[4] if len(parts) > 4 else ""
            if sub == "BEGIN":
                bp = rest.split(" ", 4)
                begin_user = bp[0] if bp else None
                begin_seen = True
            elif sub == "NGS":
                ps = rest.split(" ")
                if len(ps) >= 4 and ch == "@":
                    try:
                        fk = int(ps[0]); k = int(ps[1]); v = P.from_b36(ps[2]); is_n = (ps[3] == "N")
                        ngs_to_me.append((frm, fk, k, v, is_n))
                    except: pass
            elif sub == "BR":
                ps = rest.split(" ", 1)
                if len(ps) >= 2:
                    try: br_seen[int(ps[0])] = (frm, P.from_b36(ps[1]))
                    except: pass
            elif sub == "PR":
                try: pr_t = P.from_b36(rest.strip())
                except: pass
            elif sub == "JACCUSE":
                break

        if pr_t is not None:
            chosen_count += 1
            n_my_positions += 1
            n_per_key = defaultdict(int)
            for frm, fk, k, v, is_n in ngs_to_me:
                if is_n: n_per_key[k] = (n_per_key[k] + v) % q
            # Self-NGS-N missing because server filters self-DMs
            K_us_old = K
            self_n_contribution = (K_us_old * ((q - my_r_recomm) % q)) % q
            for k in list(n_per_key.keys()):
                n_per_key[k] = (n_per_key[k] + self_n_contribution) % q
            this_evals = {}
            for k, sn in n_per_key.items():
                fp_k = (sn + pr_t) % q
                collected_evals.append((nonce, k, fp_k))
                this_evals[k] = fp_k
            print(f"  *** cycle {cycle}: CHOSEN! K_new={n_my_positions}, evals keys={sorted(n_per_key.keys())} ngs={len(ngs_to_me)} br={len(br_seen)} ***")
            sheriff_users = [u for u in sheriff_users if u not in dead_set] + [me]
            kill_needed = True
            if len(this_evals) >= 5:
                pts = list(this_evals.items())[:5]
                secret_guess = P.lagrange_at0(pts, q)
                try:
                    bs = secret_guess.to_bytes(64, 'little').rstrip(b'\0')
                    print(f"  *** RECOVERED secret (cycle {cycle}, poly {nonce}): {bs!r}")
                    # Verify it looks like a valid alphanumeric string
                    if all(0x20 <= b < 0x7f for b in bs):
                        recovered_secret = bs.decode('ascii')
                        print(f"  *** secret={recovered_secret!r} ***")
                        break
                except Exception as e:
                    print(f"  -> conv err: {e}")
        drain(c, 0.3)

    print(f"\n[final] chosen_count={chosen_count}, elapsed={time.time()-game_start:.1f}s")

    if recovered_secret is None:
        # Try recovery from all collected_evals
        by_poly = defaultdict(dict)
        for nonce, k, v in collected_evals:
            by_poly[nonce][k] = v
        for nonce, evals in by_poly.items():
            if len(evals) >= 5:
                pts = list(evals.items())[:5]
                sg = P.lagrange_at0(pts, q)
                bs = sg.to_bytes(64, 'little').rstrip(b'\0')
                print(f"  [final attempt poly {nonce}]: {bs!r}")
                if all(0x20 <= b < 0x7f for b in bs):
                    recovered_secret = bs.decode('ascii')
                    print(f"  -> recovered: {recovered_secret!r}")
                    break

    if recovered_secret is None:
        print("[!] FAILED to recover secret")
        return

    # === Phase 3: GOODBYE → resend guess to defeat race ===
    # in_thread (running during game) consumes anything from stdin and forwards
    # to nc. After nc dies, in_thread reads guess then drops it on broken pipe.
    # Solution: send guess multiple times. At least one will land AFTER in_thread
    # exits, ending up in orchestrator's stdin buffer for read_line.
    print(f"[+] sending GOODBYE; elapsed={time.time()-game_start:.1f}s")
    try:
        c.send("GOODBYE")
    except OSError as e:
        print(f"send goodbye err: {e}")

    flag_seen = False
    # Send guess repeatedly while listening for flag
    end_wait = time.time() + 50
    last_send = 0
    while time.time() < end_wait and not flag_seen:
        # Periodically resend guess (every 3s)
        if time.time() - last_send > 3:
            try:
                c.send(recovered_secret)
                last_send = time.time()
            except OSError as e:
                print(f"send guess err: {e}")
        ln = c.recv(0.5)
        if ln is None: continue
        clean = ANSI.sub('', ln)
        print(f"[recv] {clean}")
        if "flag" in clean.lower() or "bbb{" in clean or "flag{" in clean or "ghost" in clean.lower():
            print(f"\n!!! FOUND FLAG !!!")
            flag_seen = True
            break

    # Save full transcript
    try:
        with open(r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve/live_v5.txt", "w", encoding="utf-8") as f:
            for ts, ln in c.all:
                f.write(f"{ts:.3f}\t{ln}\n")
    except Exception: pass

    c.close()


if __name__ == "__main__":
    main()
