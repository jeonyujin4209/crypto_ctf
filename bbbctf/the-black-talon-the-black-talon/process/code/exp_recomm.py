"""Trigger a recommittee by killing a committee bot. Capture all messages.
Verify the math: t = secret + sum_j my_r_j.
"""
import sys, os, time, subprocess, random
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"
PROT = "vulture"
SHERIFF = "sheriffx"
SECRET = "TheBlackTalonSecret123456789AlphaNumZxyABCDEFGH9876543210!AAAAAz"[:64]


def env(): e = os.environ.copy(); e["MSYS_NO_PATHCONV"] = "1"; return e


def setup_bots(n=50):
    return subprocess.Popen([
        "docker", "exec", "-d", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--multiple-clients", str(n)], env=env())


def launch_sheriff():
    return subprocess.Popen([
        "docker", "exec", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--force-user", PROT, "--username", SHERIFF,
        "--secret", SECRET], env=env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def kill_bot_inside_container(bot_name):
    """Find the bot's pid and kill it. The bot is a thread inside the client process —
    can't kill individual bot. Instead, we'll just SIGKILL the entire bot process and re-spawn fewer."""
    pass  # placeholder


def reset():
    subprocess.run(["docker", "restart", "talon-net"], capture_output=True)
    time.sleep(1)


def main():
    reset()
    secret_int = int.from_bytes(SECRET.encode(), "little")
    print(f"[+] secret_int = {hex(secret_int)[:60]}...")
    print(f"[+] secret bits = {secret_int.bit_length()}")

    setup_bots(50)
    time.sleep(4)
    c = Conn()
    c.recv(2)
    c.send(f"CONNECT {PROT}")
    pwd = c.recv(2).split(" ", 1)[1]
    c.send(f"JOIN {CHAN}")
    c.recv(2)

    sheriff = launch_sheriff()

    # Collect COMMITMENTS + SHARE
    info = {"cm": None, "sh": None}
    end = time.time() + 12
    while time.time() < end:
        line = c.recv(0.3)
        if line is None:
            continue
        m = parse_msg(line)
        if not m:
            continue
        _, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            info["cm"] = P.parse_commitments(msg)
            info["cm"]["sheriff"] = frm
        elif msg.startswith("SHARE "):
            info["sh"] = P.parse_share(msg)
        if info["cm"] and info["sh"]:
            break
    if not info["cm"] or not info["sh"]:
        print("[-] no initial setup")
        return

    cm = info["cm"]
    sh = info["sh"]
    q = cm["q"]; g = cm["g"]; p = 2 * q + 1
    print(f"[+] q bits={q.bit_length()}, p bits={p.bit_length()}")
    print(f"[+] commits[0]==g^secret? {pow(g, secret_int, p) == cm['commits'][0]}")
    print(f"[+] our_share key={sh['key']} valid? {P.is_share_valid(q, g, cm['commits'], sh['key'], sh['value'])}")
    print(f"[+] committee: {cm['users']}")
    print(f"[+] our position in committee: {cm['users'].index(PROT) + 1}")

    # KILL ALL bot processes inside the container (we'll then recreate fewer)
    # Actually, the issue: bots run in ONE process (--multiple-clients=50). Can't kill one.
    # To trigger recommittee, we make ourselves inactive momentarily — but we want to STAY.
    # Alternative: kill some bots by spawning fewer, OR use the docker exec to kill the bot
    # process entirely then it triggers all-inactive => panic. Need 35+ alive.
    #
    # Workaround: spawn a SECOND set of bots later, then kill the first batch.
    # But for THIS experiment, just observe the natural occurence.
    #
    # Easier: subscribe and wait. Bots will quit naturally with low probability.
    # Or, just disconnect us briefly (we are in committee, makes us inactive).
    #
    # Best: trigger by sending fake Propose ourselves. But Propose requires inactive committee member.

    # Bots Propose only every 100s. We need to be inactive for 100+ sec
    # so when their next timer fires, they see us inactive.
    print("\n[+] disconnecting for 110s to await bot Propose...")
    c.close()
    time.sleep(110)
    # Reconnect with password
    c2 = Conn()
    c2.recv(2)
    c2.send(f"RECONNECT {PROT} {pwd}")
    print("RECONNECT:", c2.recv(2))
    c2.send(f"JOIN {CHAN}")
    print("JOIN:", c2.recv(2))

    print("[+] now collecting recommittee messages for 30s...")
    recomm_msgs = []
    end = time.time() + 30
    while time.time() < end:
        line = c2.recv(0.3)
        if line is None:
            continue
        m = parse_msg(line)
        if not m:
            continue
        ch, frm, msg = m
        if "RECOMM" in msg:
            recomm_msgs.append((frm, msg))

    print(f"[+] collected {len(recomm_msgs)} recomm messages")

    # Group by sub-type
    by_type = {}
    for frm, msg in recomm_msgs:
        parts = msg.split(" ", 4)  # RECOMM ident nonce SUB rest
        sub = parts[3] if len(parts) > 3 else "?"
        by_type.setdefault(sub, []).append((frm, msg))
    for k, v in by_type.items():
        print(f"  {k}: {len(v)} msgs (e.g. from {v[0][0]})")

    # Extract BR values
    br_msgs = by_type.get("BR", [])
    pr_msgs = by_type.get("PR", [])
    print(f"\n[+] BR values seen:")
    br_kv = []
    for frm, msg in br_msgs[:15]:
        parts = msg.split(" ")
        key = int(parts[4]); value = P.from_b36(parts[5])
        br_kv.append((frm, key, value))
        print(f"  {frm}: key={key}, value={hex(value)[:60]}...")

    if pr_msgs:
        frm, msg = pr_msgs[0]
        t_val = P.from_b36(msg.split(" ")[4])
        print(f"\n[+] t (from PR): {hex(t_val)[:80]}...")

        # Now compute: if we know our own t_share, can we verify?
        # Our t_share = f(our_key) + sum_j r_j(our_key). We have f(our_key) (our share).
        # If we add up sum_j r_j(our_key) — we received r DMs.
        # But we just reconnected; we missed the NGS DMs.
        # We CAN, however, check the interpolation: t == lagrange(BR_kv at 0).
        if len(br_kv) >= 5:
            uniq = []
            seen = set()
            for f, k, v in br_kv:
                if k not in seen:
                    seen.add(k)
                    uniq.append((k, v))
                if len(uniq) >= 10:
                    break
            t_interp = P.lagrange_at0(uniq, q)
            print(f"[+] t_interp = {hex(t_interp)[:80]}...")
            print(f"[+] match? {t_interp == t_val}")

    c2.close()
    sheriff.terminate(); sheriff.wait()


if __name__ == "__main__":
    main()
