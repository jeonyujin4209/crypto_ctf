"""Full attack on LOCAL docker server.

Strategy:
1. Get sheriff committee + share.
2. KILL 5 committee bots via forged Commitments + NGS panic on fake user.
3. Sheriff's recommittee triggers (5 committee members dead → all_active fails).
4. For each cycle:
   a. Send Propose for sheriff's ident.
   b. We NUC at all K positions (K = our count in share_info.users).
   c. Wait for bots' NUC + NUR.
   d. Observe bots' NUR values, compute X = XOR.
   e. For each subset S of our K NURs, compute r_S = X XOR (XOR of S).
   f. Find subset S where r_S mod len(active_users) = idx(us).
   g. NUR our subset.
   h. Send Begin with user=us.
   i. Wait for outcome.
   j. If recommittee completes (NGS/BR/PR observed): K += 1. Collect data.
5. When K = 4 → 5 positions in new_users → 5 evals → solve.
"""
import sys, os, time, subprocess, random, threading, functools
print = functools.partial(print, flush=True)
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P
from collections import defaultdict

CHAN = "saloon"; PROT = "vulture"; SHERIFF = "sheriffx"
SECRET = ("YXY" * 22)[:64]


def env(): e = os.environ.copy(); e["MSYS_NO_PATHCONV"] = "1"; return e

def setup_bots(n=50):
    return subprocess.Popen(["docker", "exec", "-d", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--multiple-clients", str(n)], env=env())

def launch_sheriff():
    return subprocess.Popen(["docker", "exec", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--force-user", PROT, "--username", SHERIFF,
        "--secret", SECRET], env=env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def reset():
    subprocess.run(["docker", "restart", "talon-net"], capture_output=True); time.sleep(1)

def peek(c):
    c.send(f"PEEK {CHAN}")
    end = time.time() + 2
    while time.time() < end:
        r = c.recv(0.1)
        if r and r.startswith("USERS "):
            return r.split(" ", 1)[1].split(" ")
    return None

def drain(c, dur=0.3):
    """Drain only ACK/ERROR lines (not MSGFROM). Re-queue MSGFROMs (capped)."""
    end = time.time() + dur
    requeued = []
    while time.time() < end:
        ln = c.recv(0.05)
        if ln is None: break
        if ln == "ACK" or ln.startswith("ERROR") or ln.startswith("USERS ") or ln.startswith("CHANNELS"):
            pass  # discard
        else:
            if len(requeued) < 500:  # cap re-queue
                requeued.append(ln)
    # Re-queue (limit total)
    for ln in requeued:
        c.q.put(ln)


def main():
    reset(); setup_bots(50); time.sleep(4)
    c = Conn(); c.recv(2); c.send(f"CONNECT {PROT}")
    c.recv(2); c.send(f"JOIN {CHAN}"); c.recv(2)
    peek(c)  # warm up
    sheriff = launch_sheriff()

    # Get sheriff's info
    cm = sh = None
    end = time.time() + 10
    while time.time() < end and (cm is None or sh is None):
        ln = c.recv(0.3)
        if ln is None: continue
        m = parse_msg(ln)
        if not m: continue
        _, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            cm = P.parse_commitments(msg); cm["sheriff"] = frm
        elif msg.startswith("SHARE "):
            sh = P.parse_share(msg)

    q = cm["q"]; g = cm["g"]; p = 2*q+1
    sheriff_ident = cm['ident']
    print(f"[+] committee: {cm['users']}, our_key={sh['key']}")
    # Only keep relevant messages in queue (drop USER PEEK responses, irrelevant traffic)
    def _filter(s):
        if s == "ACK" or s.startswith("ERROR") or s.startswith("USERS ") or s.startswith("CHANNELS"):
            return True  # need these for protocol
        if not s.startswith("MSGFROM "):
            return True
        # Keep RECOMM for sheriff_ident or ANY ident starting with "K" (kill_ident)
        return f"RECOMM {sheriff_ident}" in s or "RECOMM K" in s or "COMMITMENTS" in s or "SHARE " in s or "RELEASED " in s
    c.line_filter = _filter
    drain(c, 1)

    dead_victims = []  # filled after kill_one_bot call below

    # ===== PHASE 2: Drive sheriff's recommittees =====
    me = PROT
    sheriff_users = list(cm['users'])  # our local view of committee
    n_my_positions = sheriff_users.count(me)  # how many times us in share_info.users
    dead_set = set(dead_victims)
    print(f"[+] our positions in sheriff_users: {n_my_positions}")

    collected_evals = []  # list of (k, share_value, nonce) for f^(nonce)
    chosen_count = 0
    cycle = 0
    MAX_CYCLES = 1500
    CYCLE_DEADLINE = time.time() + 1200

    kill_counter = 0  # ident suffix for forged attacks
    kill_needed = False  # set when previous recommittee succeeded and we need to kill a bot

    def kill_one_bot(target_name, my_us_in_chan):
        """Kill 1 bot via forged Commitments + NGS panic.
        users = [target, us×4, fake]. K=4 us positions + target = 5 entities.
        After all NUC + NUR (subset size >=4 for rs.len>=5), Begin with user=target or us.
        Engineer NUR subset such that r mod active_users.len = idx(target or us) in active.
        """
        nonlocal kill_counter
        kill_counter += 1
        kill_ident = f"K{kill_counter:08d}"
        # 6 us positions for high P(match)
        forged_users = [target_name] + [my_us_in_chan] * 6 + ["fake_dead_zz"]
        cs_str = ",".join(P.b36(x) for x in [g, 1, 1, 1, 1])
        us_str = ",".join(forged_users)
        c.send(f"MSG {CHAN} COMMITMENTS {kill_ident} {P.b36(q)} {P.b36(g)} {cs_str} {us_str}")
        drain(c, 0.3)
        c.send(f"MSG @{target_name} SHARE {kill_ident} 1 1")
        drain(c, 0.1)
        c.send(f"MSG @{my_us_in_chan} SHARE {kill_ident} 1 1")
        drain(c, 0.5)  # ensure bot has registered commitments + share before propose
        nk = random.randint(1, 2**32-2)
        c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} PROPOSE")
        our_s_list = [random.randint(0, (1<<64)-1) for _ in range(6)]
        for s in our_s_list:
            c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} NUC {P.b36(pow(g, s, q))}")
        # Wait for target's NUC + NUR — extended
        target_s = None
        end = time.time() + 5.0
        while time.time() < end:
            if target_s is not None: break  # got it, exit early
            ln = c.recv(0.15)
            if ln is None: continue
            m = parse_msg(ln)
            if not m: continue
            ch, frm, msg = m
            if frm != target_name: continue
            if not msg.startswith(f"RECOMM {kill_ident} {nk}"): continue
            parts = msg.split(" ", 4)
            if len(parts) >= 5 and parts[3] == "NUR":
                try: target_s = int(parts[4].strip())
                except: pass

        # Choose subset of size >=4 (to ensure rs.len>=5) such that r mod N matches idx(target or us)
        active = None
        for _ in range(5):
            active = peek(c)
            if active: break
            time.sleep(0.2)
        if not active:
            return  # cannot continue this kill
        target_idx = active.index(target_name) if target_name in active else -1
        us_idx = active.index(my_us_in_chan) if my_us_in_chan in active else -1
        N = len(active)
        chosen_subset = None
        chosen_user = None
        if target_s is not None:
            # rs.len = target_NUR(1) + our_subset_size. Need >= 5 → subset >= 4.
            for bitmask in range(1 << 6):
                if bin(bitmask).count("1") < 4: continue
                our_xor = 0
                for i in range(6):
                    if bitmask & (1 << i):
                        our_xor ^= our_s_list[i]
                r = target_s ^ our_xor
                idx = r % N
                if idx == target_idx:
                    chosen_subset = bitmask; chosen_user = target_name; break
                elif idx == us_idx:
                    chosen_subset = bitmask; chosen_user = my_us_in_chan; break

        if chosen_subset is None:
            chosen_subset = (1 << 6) - 1; chosen_user = my_us_in_chan

        # Debug
        print(f"      [kill {kill_ident}] target_s={'OK' if target_s is not None else 'NONE'} target_idx={target_idx} us_idx={us_idx} N={N} chosen={chosen_user==target_name and 'TARGET' or 'US'}")

        # Send chosen subset of our NURs
        for i in range(6):
            if chosen_subset & (1 << i):
                c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} NUR {our_s_list[i]}")
                drain(c, 0.05)
        # Also send our own Begin so target doesn't have to wait for 3s timeout.
        bu = ",".join(forged_users)
        c.send(f"MSG {CHAN} RECOMM {kill_ident} {nk} BEGIN {chosen_user} {my_us_in_chan} {P.b36(q)} {P.b36(g)} {bu}")
        # Wait at least 7s: bot does 3s sleep after NGC + iterates NGS.
        drain(c, 8.0)

    # Initial kill: kill 1 committee bot to enable first Propose
    initial_victim = [u for u in cm['users'] if u != PROT][0]
    print(f"[+] initial kill: {initial_victim}")
    for retry in range(3):
        kill_one_bot(initial_victim, me)
        drain(c, 1.0)
        after = peek(c)
        if initial_victim not in after:
            dead_set.add(initial_victim); dead_victims.append(initial_victim)
            print(f"  -> {initial_victim} dead (active: {len(after)})")
            break
        else:
            print(f"  -> retry {retry+1}/3")
    if not dead_victims:
        print("[-] initial kill failed; aborting")
        return

    while cycle < MAX_CYCLES and time.time() < CYCLE_DEADLINE and not c.dead:
        cycle += 1
        if cycle <= 10 or cycle % 20 == 0:
            print(f"cycle {cycle} starting, dead={c.dead}, elapsed={time.time()-(CYCLE_DEADLINE-250):.1f}s")

        if kill_needed and len(sheriff_users) > 1:
            target = next((u for u in sheriff_users if u != me and u not in dead_set), None)
            if target:
                print(f"  cycle {cycle}: trying to kill {target}")
                kill_one_bot(target, me)
                drain(c, 1.0)
                # Verify kill via peek
                after = peek(c)
                if target not in after:
                    dead_set.add(target)
                    print(f"    -> {target} confirmed dead (active count: {len(after)})")
                    kill_needed = False
                else:
                    print(f"    -> {target} STILL ALIVE; retry next cycle")
        # Trigger Propose
        nonce = random.randint(1, 2**32 - 2)
        c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} PROPOSE")
        drain(c, 0.3)

        # Our NUCs (one per position)
        my_s_list = [random.randint(0, (1<<64)-1) for _ in range(n_my_positions)]
        for s in my_s_list:
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} NUC {P.b36(pow(g, s, q))}")
            drain(c, 0.05)

        # Expected bot NURs = alive non-us committee members
        alive_bot_count = sum(1 for u in sheriff_users if u != me and u not in dead_set)
        # Wait for bot NUCs and NURs — wait until all alive bots NUR or timeout
        nurs = {}
        commits_seen = {}
        end = time.time() + 6.0  # extended for high-K cycles
        last_nur_time = time.time()
        while time.time() < end:
            # Early exit: got all alive bot NURs
            if len(nurs) >= alive_bot_count:
                break
            ln = c.recv(0.15)
            if ln is None: continue
            m = parse_msg(ln)
            if not m: continue
            _, frm, msg = m
            if msg.startswith(f"RECOMM {sheriff_ident} {nonce}"):
                parts = msg.split(" ", 4)
                sub = parts[3]
                if sub == "NUR":
                    try:
                        nurs[frm] = int(parts[4].strip())
                        last_nur_time = time.time()
                    except: pass
                elif sub == "NUC":
                    commits_seen[frm] = parts[4]

        K = len(my_s_list)
        # CRITICAL: if we missed ANY bot NUR, bots' XOR != ours → cycle will fail silently.
        # Abort early if we don't have ALL alive bot NURs.
        if len(nurs) < alive_bot_count:
            if cycle % 3 == 0:
                print(f"  cycle {cycle}: nurs={len(nurs)}/{alive_bot_count} K={K} - missing bot NURs, skip")
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} JACCUSE abort")
            drain(c, 0.3)
            continue
        if len(nurs) + K < 5:
            if cycle % 3 == 0:
                print(f"  cycle {cycle}: len(commits)={len(commits_seen)} len(nurs)={len(nurs)} K={K} - insufficient (need {5-K})")
            c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} JACCUSE abort")
            drain(c, 0.3)
            continue

        # Get current active users
        active = peek(c)
        if me not in active:
            print(f"[!] WE'RE NOT IN ACTIVE_USERS, something wrong")
            break
        my_idx_in_active = active.index(me)
        N = len(active)

        # Compute X = XOR of bots' NUR values
        X = 0
        for v in nurs.values(): X ^= v

        # For each subset where (len(nurs) + popcount) >= 5, find one where r mod N = my_idx_in_active.
        K = len(my_s_list)
        target_subset = None
        min_subset_size = max(0, 5 - len(nurs))
        for bitmask in range(0, 1 << K):
            if bin(bitmask).count("1") < min_subset_size: continue
            our_xor = 0
            for i in range(K):
                if bitmask & (1 << i):
                    our_xor ^= my_s_list[i]
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

        # NUR the chosen subset
        for i in range(K):
            if target_subset & (1 << i):
                c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} NUR {my_s_list[i]}")
                drain(c, 0.05)
        drain(c, 0.3)

        # Send our own Begin with user=us. Bots verify with their own r computation.
        begin_users = ",".join(sheriff_users)
        begin_msg = f"BEGIN {me} {cm['sheriff']} {P.b36(q)} {P.b36(g)} {begin_users}"
        c.send(f"MSG {CHAN} RECOMM {sheriff_ident} {nonce} {begin_msg}")
        drain(c, 0.5)

        # NOW we play the role of an old committee member with share.
        # Send NGC at our position (use trivial r/n polys with all-1 higher coefs).
        # Choose my_r ∈ [0, q). r_commits = [g^my_r, 1, 1, 1, 1]; n_commits = [g^(q-my_r), 1, 1, 1, 1].
        my_r_recomm = random.randint(0, q-1)
        our_us_pos_in_sheriff = sheriff_users.index(me) + 1  # first occurrence, 1-indexed
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

        # Construct new_users like bots would.
        new_users_view = list(sheriff_users) + [me]
        # Prune dead victims
        new_users_view = [u for u in new_users_view if u not in dead_set]

        # Send NGS R DMs to each old committee bot at their key, value = my_r.
        # And N DMs to each new user at their new position, value = (q - my_r).
        # Use 1 NGS per (our pos, recipient).
        my_r_b36 = P.b36(my_r_recomm)
        q_minus_r = (q - my_r_recomm) % q
        n_val_b36 = P.b36(q_minus_r)
        # For R, iterate sheriff_users
        for pos in range(len(sheriff_users)):
            recipient = sheriff_users[pos]
            if recipient == me: continue  # self-DM not needed (we count locally)
            if recipient in dead_set: continue  # don't bother
            key = pos + 1
            # From_key = our position. For us at multiple positions, we use first occurrence index+1.
            for our_pos_idx, u in enumerate(sheriff_users):
                if u == me:
                    from_key = our_pos_idx + 1
                    c.send(f"MSG @{recipient} RECOMM {sheriff_ident} {nonce} NGS {from_key} {key} {my_r_b36} R")
                    drain(c, 0.02)
        # For N, iterate new_users_view
        for npos, recipient in enumerate(new_users_view):
            key = npos + 1
            if recipient == me: continue
            for our_pos_idx, u in enumerate(sheriff_users):
                if u == me:
                    from_key = our_pos_idx + 1
                    c.send(f"MSG @{recipient} RECOMM {sheriff_ident} {nonce} NGS {from_key} {key} {n_val_b36} N")
                    drain(c, 0.02)
        drain(c, 0.5)

        # Send our BR. Need to know our share value and sum r_j(our_old_key).
        # We need to RECEIVE R DMs from other bots first to compute sum.
        # Collect any R DMs to us during waiting.
        # Initialize state for this cycle
        begin_user = None
        begin_seen = False
        ngs_to_me = []
        br_seen = {}
        pr_t = None

        received_r_for_us = {}
        end_collect = time.time() + 4
        while time.time() < end_collect:
            ln = c.recv(0.2)
            if ln is None: continue
            m = parse_msg(ln)
            if not m: continue
            ch, frm, msg = m
            if not msg.startswith(f"RECOMM {sheriff_ident} {nonce}"): continue
            parts = msg.split(" ", 4)
            if len(parts) < 5: continue
            sub = parts[3]; rest = parts[4]
            if sub == "NGS" and ch == "@":
                ps = rest.split(" ")
                if len(ps) >= 4:
                    try:
                        fk = int(ps[0]); k = int(ps[1]); v = P.from_b36(ps[2]); is_n = (ps[3] == "N")
                        if is_n:
                            ngs_to_me.append((frm, fk, k, v, True))
                        else:
                            received_r_for_us[fk] = v
                            ngs_to_me.append((frm, fk, k, v, False))
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

        # Don't send our BR — would collide with bots' BR at our shifted key after first R.
        # Bots have ≥5 alive members to BR on their own. We only need PR (broadcast) to learn t.

        # Continue waiting for NGC/NGS/BR/PR. Don't reset accumulated state.
        end = time.time() + 10
        while time.time() < end:
            ln = c.recv(0.3)
            if ln is None: continue
            m = parse_msg(ln)
            if not m: continue
            ch, frm, msg = m
            if msg.startswith("RELEASED"):
                print(f"!! RELEASED to us: {msg[:200]}")
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
            # MISSING: server filters self-DMs, so our own K us-positions × NGS N to us
            # are not in ngs_to_me. Each value = q - my_r_recomm. Add manually for each k.
            K_us_old = K  # K = len(my_s_list) = us positions in OLD committee
            self_n_contribution = (K_us_old * ((q - my_r_recomm) % q)) % q
            for k in list(n_per_key.keys()):
                n_per_key[k] = (n_per_key[k] + self_n_contribution) % q
            this_evals = {}
            for k, sn in n_per_key.items():
                fp_k = (sn + pr_t) % q
                collected_evals.append((nonce, k, fp_k))
                this_evals[k] = fp_k
            print(f"  *** cycle {cycle}: CHOSEN! K_new={n_my_positions}, evals: keys={sorted(n_per_key.keys())} ngs={len(ngs_to_me)} br={len(br_seen)} ***")
            sheriff_users = [u for u in sheriff_users if u not in dead_set] + [me]
            print(f"    new sheriff_users: {sheriff_users}, n_my={sheriff_users.count(me)}")
            kill_needed = True  # next cycle needs to kill a bot to trigger Propose
            # Try immediate recovery if ≥ 5 evals for THIS polynomial
            if len(this_evals) >= 5:
                pts = list(this_evals.items())[:5]
                secret_guess = P.lagrange_at0(pts, q)
                try:
                    bs = secret_guess.to_bytes(64, 'little').rstrip(b'\0')
                    print(f"  *** RECOVERED secret (cycle {cycle}, poly {nonce}): {bs!r}")
                    if bs == SECRET.encode():
                        print(f"  *** MATCH! exiting ***")
                        break
                except Exception as e:
                    print(f"  -> conv err: {e}")
        else:
            if cycle % 5 == 0:
                print(f"  cycle {cycle}: K={K} N={N} subset OK; no PR (ngs={len(ngs_to_me)} br={len(br_seen)} begin_seen={begin_seen})")
        drain(c, 0.3)

    print(f"\n[final] chosen_count={chosen_count}, n_my_positions={n_my_positions}")
    print(f"[final] collected_evals: {len(collected_evals)}")

    # Group evaluations by nonce (= per polynomial)
    by_poly = defaultdict(list)
    for nonce, k, v in collected_evals:
        by_poly[nonce].append((k, v))
    for nonce, evals in by_poly.items():
        print(f"  poly nonce={nonce}: {len(evals)} evals at keys {sorted(set(k for k,_ in evals))}")
        # If ≥ 5 evals at distinct keys, recover f' (poly degree 4)
        unique_evals = {}
        for k, v in evals:
            if k not in unique_evals: unique_evals[k] = v
        if len(unique_evals) >= 5:
            pts = list(unique_evals.items())[:5]
            secret_guess = P.lagrange_at0(pts, q)
            # Convert to bytes
            try:
                bs = secret_guess.to_bytes(64, 'little')
                # Strip trailing zeros
                bs = bs.rstrip(b'\0')
                print(f"  *** RECOVERED secret_guess (poly {nonce}): {bs!r}")
                if bs == SECRET.encode():
                    print(f"  *** MATCH! ***")
            except Exception as e:
                print(f"  -> conv err: {e}")

    c.send("GOODBYE"); c.close()
    sheriff.terminate(); sheriff.wait()


if __name__ == "__main__":
    main()
