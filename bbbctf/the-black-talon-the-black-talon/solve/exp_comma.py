"""Test: name with a comma — does it split the users list and corrupt protocol?"""
import sys, os, time, subprocess
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"
SHERIFF = "sheriffx"
SECRET = ("TheBlackTalonSecret123456789AlphaNumZxyABCDEFGH9876543210!AAAAAz")[:64]


def setup_bots(n=50):
    env = os.environ.copy(); env["MSYS_NO_PATHCONV"] = "1"
    return subprocess.Popen([
        "docker", "exec", "-d", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--multiple-clients", str(n)], env=env)


def launch_sheriff(prot):
    env = os.environ.copy(); env["MSYS_NO_PATHCONV"] = "1"
    return subprocess.Popen([
        "docker", "exec", "talon-net",
        "/bin/talon/client", "--server", "127.0.0.1", "--port", "31337",
        "--channel", CHAN, "--force-user", prot, "--username", SHERIFF,
        "--secret", SECRET], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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
    info = {"commits": None, "share": None, "all": []}
    end = time.time() + timeout
    while time.time() < end:
        line = c.recv(0.5)
        if line is None:
            continue
        info["all"].append(line)
        m = parse_msg(line)
        if not m:
            continue
        ch, frm, msg = m
        if msg.startswith("COMMITMENTS"):
            info["commits"] = P.parse_commitments(msg)
            info["commits"]["sheriff"] = frm
            info["commits"]["raw"] = msg
        elif msg.startswith("SHARE "):
            info["share"] = P.parse_share(msg)
        if info["commits"] and info["share"]:
            return info
    return info


def try_name(prot_name):
    print(f"\n=== TEST: prot={prot_name!r} ===")
    setup_bots(50); time.sleep(4)
    c = Conn()
    c.recv(2)
    c.send(f"CONNECT {prot_name}")
    r = c.recv(2)
    print(f"  CONNECT response: {r}")
    if not r.startswith("NEWUSER"):
        print(f"  -> rejected")
        c.close(); return
    c.send(f"JOIN {CHAN}")
    print(f"  JOIN: {c.recv(2)}")

    wait_for_bots(c, 50)
    sheriff = launch_sheriff(prot_name)
    info = fetch_initial(c)

    if info["commits"]:
        print(f"  parsed COMMITMENTS users count: {len(info['commits']['users'])}")
        print(f"  parsed users: {info['commits']['users']}")
        am_i_there = prot_name in info['commits']['users']
        print(f"  full prot name in users (exact)?: {am_i_there}")
    if info["share"]:
        print(f"  got SHARE key={info['share']['key']}")
    else:
        print(f"  no SHARE received")
    c.send("GOODBYE"); c.close()
    sheriff.terminate(); sheriff.wait()


# Baseline
try_name("vulture")
# Comma split
docker_restart = subprocess.run(["docker", "restart", "talon-net"], capture_output=True)
time.sleep(1)
try_name("foo,sheriffx")
