"""Observer pattern: observer stays in saloon throughout, vulture disconnects to trigger recommittee."""
import sys, os, time, subprocess, threading
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
from client import Conn, parse_msg
import proto as P

CHAN = "saloon"; PROT = "vulture"; SHERIFF = "sheriffx"
SECRET = "TheBlackTalonSecret123456789AlphaNumZxyABCDEFGH9876543210!AAAAAz"[:64]


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


def main():
    reset()
    secret_int = int.from_bytes(SECRET.encode(), "little")

    setup_bots(50); time.sleep(4)

    # Observer stays connected; vulture disconnects
    obs = Conn(); obs.recv(2); obs.send("CONNECT observer")
    obs.recv(2); obs.send(f"JOIN {CHAN}"); obs.recv(2)
    vult = Conn(); vult.recv(2); vult.send(f"CONNECT {PROT}")
    pwd = vult.recv(2).split(" ", 1)[1]
    vult.send(f"JOIN {CHAN}"); vult.recv(2)

    sheriff = launch_sheriff()

    # Wait for vulture's SHARE
    info = {"cm": None, "sh": None}
    end = time.time() + 15
    while time.time() < end and (info["cm"] is None or info["sh"] is None):
        for c, key in [(obs, "obs"), (vult, "vult")]:
            line = c.recv(0.1)
            if line is None:
                continue
            m = parse_msg(line)
            if not m:
                continue
            _, frm, msg = m
            if msg.startswith("COMMITMENTS") and not info["cm"]:
                info["cm"] = P.parse_commitments(msg)
                info["cm"]["sheriff"] = frm
                print(f"[{key}] got COMMITMENTS")
            elif msg.startswith("SHARE ") and not info["sh"] and key == "vult":
                info["sh"] = P.parse_share(msg)
                print(f"[{key}] got SHARE key={info['sh']['key']}")

    cm = info["cm"]; sh = info["sh"]
    q = cm["q"]; g = cm["g"]; p = 2 * q + 1
    print(f"[+] committee: {cm['users']}, our_key={sh['key']}")

    # Now disconnect vulture for 110s+ to trigger natural Propose timer
    print("[+] vulture disconnecting; observer keeps listening...")
    vult.close()

    # Drain observer messages continuously during the wait
    collected = []
    def drain_obs():
        while True:
            line = obs.recv(0.5)
            if line is None:
                if obs.dead:
                    return
                continue
            m = parse_msg(line)
            if m:
                _, frm, msg = m
                if "RECOMM" in msg:
                    collected.append((time.time(), frm, msg))

    t = threading.Thread(target=drain_obs, daemon=True); t.start()

    time.sleep(150)  # wait for bot timer + recommittee
    print(f"\n[+] observer collected {len(collected)} RECOMM messages")

    by_type = {}
    for tt, frm, msg in collected:
        sub = msg.split(" ", 4)[3] if len(msg.split(" ")) > 3 else "?"
        by_type.setdefault(sub, []).append((tt, frm, msg))

    for k, v in by_type.items():
        print(f"  {k}: {len(v)} msgs")

    # Verify t leak
    br_msgs = by_type.get("BR", [])
    pr_msgs = by_type.get("PR", [])
    print(f"\n[+] BR distinct (by sender):")
    seen = {}
    for tt, frm, msg in br_msgs:
        parts = msg.split(" ")
        key = int(parts[4]); val = P.from_b36(parts[5])
        seen.setdefault((frm, key), val)
    for (frm, key), val in sorted(seen.items(), key=lambda x: x[0][1]):
        print(f"  [{key}] from {frm}: {hex(val)[:50]}...")

    if pr_msgs:
        t_val = P.from_b36(pr_msgs[0][2].split(" ")[4])
        print(f"\n[+] t = {hex(t_val)[:60]}...")

        # Interpolate from BR
        uniq = []; ks = set()
        for (frm, key), v in seen.items():
            if key not in ks:
                ks.add(key); uniq.append((key, v))
        if len(uniq) >= 5:
            t_interp = P.lagrange_at0(uniq[:9], q)  # use 9 if avail
            print(f"[+] t_interp({len(uniq[:9])} pts) = {hex(t_interp)[:60]}...")
            print(f"[+] match: {t_interp == t_val}")
            # Verify t corresponds to secret + sum_my_r_j
            # We can compute g^t mod p and check it equals c_0 * prod(r_commits[0])
            gt = pow(g, t_val, p)
            print(f"[+] g^t mod p = {hex(gt)[:60]}...")
            # c_0 = g^secret
            print(f"[+] c_0 = g^secret = {hex(cm['commits'][0])[:60]}...")
            print(f"[+] g^t / c_0 should = g^(sum my_r_j)")
            diff = (gt * pow(cm['commits'][0], -1, p)) % p
            print(f"[+] g^t / c_0 = {hex(diff)[:60]}...")
            # If our analysis is correct, this should equal product of all r_commits[0]
            # which we observe in NGC messages

    # Extract r_commits[0] from NGC messages
    ngc_msgs = by_type.get("NGC", [])
    print(f"\n[+] NGC count: {len(ngc_msgs)}")
    if ngc_msgs and pr_msgs:
        r_commits_0 = {}
        for tt, frm, msg in ngc_msgs:
            parts = msg.split(" ")
            key = int(parts[4])
            r_cs = parts[5].split(",")
            r0 = P.from_b36(r_cs[0])
            r_commits_0[(frm, key)] = r0
        print(f"  unique NGC senders: {len(set(k[0] for k in r_commits_0))}")
        prod = 1
        for v in r_commits_0.values():
            prod = (prod * v) % p
        print(f"[+] prod(r_commits[0]) = {hex(prod)[:60]}...")
        # If our derivation correct: g^t = c_0 * prod  i.e.,  t = secret + sum my_r_j
        expected_gt = (cm['commits'][0] * prod) % p
        print(f"[+] expected g^t = c_0 * prod = {hex(expected_gt)[:60]}...")

    obs.send("GOODBYE"); obs.close()
    sheriff.terminate(); sheriff.wait()


if __name__ == "__main__":
    main()
