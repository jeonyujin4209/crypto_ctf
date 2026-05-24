"""Full scenario: connect as protagonist, launch sheriff via docker exec, observe."""
import sys, time, subprocess, threading

sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg

CHAN = "saloon"
PROT = "vulture"
SHERIFF = "sheriffx"
SECRET = "TheBlackTalonSecret123456789AlphaNumZxyABCDEFGH9876543210!" + "AAAAA"
SECRET = SECRET[:64].ljust(64, "z")  # exactly 64 chars


def launch_sheriff():
    """Run secret_injector inside docker."""
    cmd = [
        "docker", "exec", "talon-net",
        "/bin/talon/client",
        "--server", "127.0.0.1",
        "--port", "31337",
        "--channel", CHAN,
        "--force-user", PROT,
        "--username", SHERIFF,
        "--secret", SECRET,
    ]
    import os
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    print(f"[+] secret={SECRET!r} len={len(SECRET)}")
    c = Conn()
    print(c.recv(2))
    c.send(f"CONNECT {PROT}")
    r = c.recv(2)
    print(r)
    pwd = r.split(" ", 1)[1]
    c.send(f"JOIN {CHAN}")
    print(c.recv(2))
    print(f"[+] Connected as {PROT}, pwd={pwd}")

    # Verify bots are in
    c.send(f"PEEK {CHAN}")
    r = c.recv(2)
    users = r.split(" ", 1)[1].split(" ")
    print(f"[+] {len(users)} users in {CHAN}")

    # Launch sheriff
    print("[+] launching sheriff...")
    sheriff_proc = launch_sheriff()

    # Collect messages for 15s
    start = time.time()
    all_messages = []
    while time.time() - start < 15:
        line = c.recv(1)
        if line is None:
            continue
        all_messages.append(line)
        m = parse_msg(line)
        if m:
            ch, frm, msg = m
            tag = msg.split(" ", 1)[0]
            preview = msg[:80]
            print(f"  [{ch}/{frm}] {tag}: {preview}{'...' if len(msg)>80 else ''}")

    print(f"\n[+] Total messages: {len(all_messages)}")
    c.send("GOODBYE")
    c.close()
    sheriff_proc.terminate()
    sheriff_proc.wait()


if __name__ == "__main__":
    main()
