"""Empirical probe: verify our understanding and test attacks.

Pre-req: docker network is running on :31337. We start bots from this script.
"""
import sys, os, time, subprocess
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"
PROT = sys.argv[1] if len(sys.argv) > 1 else "vulture"
SHERIFF = "sheriffx"
SECRET = "TheBlackTalonSecret123456789AlphaNumZxyABCDEFGH9876543210!AAAAAz"[:64]


def setup_bots(n=50):
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    return subprocess.Popen([
        "docker", "exec", "-d", "talon-net",
        "/bin/talon/client",
        "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--multiple-clients", str(n),
    ], env=env)


def launch_sheriff():
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    return subprocess.Popen([
        "docker", "exec", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--force-user", PROT, "--username", SHERIFF,
        "--secret", SECRET,
    ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def wait_for_bots(c, target=50, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        c.send(f"PEEK {CHAN}")
        r = c.recv(2)
        if r and r.startswith("USERS "):
            users = r.split(" ", 1)[1].split(" ")
            non_probe = [u for u in users if u != PROT and not u.startswith("__probe")]
            if len(non_probe) >= target:
                return non_probe
        time.sleep(0.5)
    return None


def fetch_initial(c, sheriff_proc, timeout=15):
    """Collect COMMITMENTS + SHARE."""
    info = {"commits": None, "share": None, "msgs": []}
    end = time.time() + timeout
    while time.time() < end:
        line = c.recv(0.5)
        if line is None:
            continue
        info["msgs"].append(line)
        m = parse_msg(line)
        if not m:
            continue
        ch, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            info["commits"] = P.parse_commitments(msg)
            info["commits"]["sheriff"] = frm
        elif msg.startswith("SHARE "):
            info["share"] = P.parse_share(msg)
        if info["commits"] and info["share"]:
            return info
    return info


def main():
    print(f"[+] secret={SECRET!r}")
    bots = setup_bots(50)
    time.sleep(4)

    c = Conn()
    print(c.recv(2))  # WELCOME
    c.send(f"CONNECT {PROT}")
    pwd_line = c.recv(2)
    pwd = pwd_line.split(" ", 1)[1]
    c.send(f"JOIN {CHAN}")
    print(c.recv(2))

    print("[+] waiting for bots...")
    bot_names = wait_for_bots(c, 50)
    assert bot_names, "bots didn't appear"
    print(f"[+] {len(bot_names)} bots in {CHAN}")

    print("[+] launching sheriff")
    sheriff = launch_sheriff()
    info = fetch_initial(c, sheriff)
    if not info["commits"]:
        print("[-] no COMMITMENTS received")
        return
    if not info["share"]:
        print("[-] no SHARE DM received (force-user may have failed)")

    cm = info["commits"]
    sh = info["share"]
    print(f"[+] ident={cm['ident']}, sheriff={cm['sheriff']}")
    print(f"[+] users (committee)={cm['users']}")
    print(f"[+] q has {cm['q'].bit_length()} bits, g={cm['g']}")
    print(f"[+] commits: {len(cm['commits'])} entries")
    if sh:
        print(f"[+] our share: key={sh['key']}, value={hex(sh['value'])[:60]}...")
        # Verify our share
        ok = P.is_share_valid(cm['q'], cm['g'], cm['commits'], sh['key'], sh['value'])
        print(f"[+] share validates against commits: {ok}")

    # ATTACK 1: send RELEASE as us — expect bots to ignore
    print("\n[ATK1] Send RELEASE as us (should be ignored)")
    c.send(f"MSG {CHAN} {P.fmt_release(cm['ident'])}")
    print(c.recv(2))  # ACK
    msgs = []
    end = time.time() + 3
    while time.time() < end:
        line = c.recv(0.5)
        if line: msgs.append(line)
    print(f"  -> Received {len(msgs)} messages after RELEASE")
    rs = [m for m in msgs if "RELEASED" in m]
    print(f"  -> ReleasedShare msgs: {len(rs)}")

    # ATTACK 2: Forged Begin with initiator=sheriff
    # First, propose a recommittee. But propose requires someone inactive.
    # The committee from cm['users'] is 10 names; check who's active.
    print("\n[ATK2] Check active committee members")
    c.send(f"PEEK {CHAN}")
    r = c.recv(2)
    active = r.split(" ",1)[1].split(" ") if r else []
    inactive_committee = [u for u in cm['users'] if u not in active]
    print(f"  inactive committee: {inactive_committee}")
    print(f"  (sheriff in active: {cm['sheriff'] in active})")

    c.send("GOODBYE")
    c.close()
    sheriff.terminate()
    sheriff.wait()
    print("[done]")


if __name__ == "__main__":
    main()
