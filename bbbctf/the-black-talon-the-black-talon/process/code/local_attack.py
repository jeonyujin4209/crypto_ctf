"""LOCAL attack: empirically test attack vectors on docker-hosted network.

Tests:
1. DM-flood DOS — kill specific bot by flooding broadcast queue.
2. Forged Commitments with non-existent user — force bot's all_active to fail.
3. Repeated recommittees with us as chosen new user.
"""
import sys, os, time, subprocess, threading, queue, socket, re, random
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"; PROT = "vulture"; SHERIFF = "sheriffx"
SECRET = ("DEADBEEF" * 8)[:64]


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


def fetch_initial(c, timeout=12):
    info = {"cm": None, "sh": None}
    end = time.time() + timeout
    while time.time() < end:
        line = c.recv(0.3)
        if line is None: continue
        m = parse_msg(line)
        if not m: continue
        _, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            info["cm"] = P.parse_commitments(msg); info["cm"]["sheriff"] = frm
        elif msg.startswith("SHARE "):
            info["sh"] = P.parse_share(msg)
        if info["cm"] and info["sh"]:
            return info
    return info


# =================== TEST 1: DM-flood DOS ===================
def test_dm_flood():
    print("\n=== TEST 1: DM-flood DOS ===")
    reset(); setup_bots(50); time.sleep(4)
    c = Conn(); c.recv(2); c.send(f"CONNECT {PROT}")
    c.recv(2); c.send(f"JOIN {CHAN}"); c.recv(2)
    users = wait_for_bots(c, 50)
    print(f"[+] {len(users)} users in {CHAN}")
    target = "qsiq_25"  # arbitrary bot name
    # Verify target exists
    if target not in users:
        # pick first non-PROT user
        target = next(u for u in users if u != PROT)
    print(f"[+] flood target: {target}")

    # Drain all incoming queue first
    while c.recv(0.05) is not None: pass

    # Send many DMs rapidly to target
    N = 2000
    payload = "X" * 100  # 100-byte payload
    t0 = time.time()
    sent = 0
    for i in range(N):
        try:
            c.send(f"MSG @{target} {payload}_{i}")
            sent += 1
        except Exception as e:
            print(f"  send err at {i}: {e}")
            break
        # Drain ACKs occasionally
        if i % 100 == 99:
            cnt = 0
            t1 = time.time()
            while time.time() - t1 < 0.1 and cnt < 200:
                r = c.recv(0.005)
                if r is None: break
                cnt += 1
    print(f"[+] sent {sent} DMs in {time.time()-t0:.2f}s")

    # Drain remaining
    time.sleep(2)
    while c.recv(0.1) is not None: pass

    # Check if target is still alive
    time.sleep(1)
    c.send(f"PEEK {CHAN}")
    r = c.recv(2)
    if r and r.startswith("USERS "):
        users_now = r.split(" ", 1)[1].split(" ")
        print(f"[+] users after flood: {len(users_now)}")
        print(f"[+] target alive: {target in users_now}")
        # Check if we're still alive
        print(f"[+] we alive: {PROT in users_now}")
    else:
        print(f"[-] PEEK failed: {r}")

    c.send("GOODBYE"); c.close()


# =================== TEST 2: Forged Commitments + Propose ===================
def test_forged_commitments():
    print("\n=== TEST 2: Forged Commitments to trigger Propose ===")
    reset(); setup_bots(50); time.sleep(4)
    c = Conn(); c.recv(2); c.send(f"CONNECT {PROT}")
    c.recv(2); c.send(f"JOIN {CHAN}"); c.recv(2)
    wait_for_bots(c, 50)
    sheriff = launch_sheriff()
    info = fetch_initial(c)
    if not info["cm"]:
        print("[-] no commitments"); return

    cm = info["cm"]
    ident = cm["ident"]; q = cm["q"]; g = cm["g"]; p = 2*q+1

    print(f"[+] real committee: {cm['users']}")

    # Now send a forged Commitments with same ident, but users containing fake_user.
    # This will OVERWRITE share_info for bots in our list. fake_user not in active_users.
    # bot's all_active fails → they Propose.

    # Choose 5 committee bots + fake + us
    target_bots = [u for u in cm['users'] if u != PROT][:5]
    fake = "fake_zzz_xxx"
    new_users = target_bots + [fake, PROT]
    print(f"[+] forged users: {new_users}")

    # Build Commitments message
    # commitments = sheriff's c0..c4 (use as is)
    commits_str = ",".join(P.b36(c_) for c_ in cm["commits"])
    users_str = ",".join(new_users)
    msg = f"COMMITMENTS {ident} {P.b36(q)} {P.b36(g)} {commits_str} {users_str}"
    print(f"[+] sending forged Commitments...")
    c.send(f"MSG {CHAN} {msg}")
    ack = c.recv(2)
    print(f"  ack: {ack}")

    # Now wait for natural events (Propose, etc.) from bot Propose
    # Bots' timer is 100s. Wait shorter to see if our forged Commitments quickly triggers.
    print(f"[+] waiting 120s for activity...")
    events = []
    end = time.time() + 120
    while time.time() < end:
        line = c.recv(0.5)
        if line is None: continue
        m = parse_msg(line)
        if not m: continue
        _, frm, mbody = m
        if "RECOMM" in mbody:
            parts = mbody.split(" ", 4)
            sub = parts[3] if len(parts) > 3 else "?"
            events.append((time.time() - (end-120), frm, sub, mbody[:80]))

    print(f"[+] {len(events)} recomm events")
    # Group by sub
    by_sub = {}
    for ts, frm, sub, body in events:
        by_sub.setdefault(sub, []).append((ts, frm))
    for sub, items in by_sub.items():
        print(f"  {sub}: {len(items)}")
    # First few
    for ts, frm, sub, body in events[:15]:
        print(f"  [{ts:5.1f}] {frm}: {sub}: {body}")

    c.send("GOODBYE"); c.close()
    sheriff.terminate(); sheriff.wait()


if __name__ == "__main__":
    test_dm_flood()
    test_forged_commitments()
