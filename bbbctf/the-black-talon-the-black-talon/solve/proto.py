"""Protocol message helpers — parse and craft."""
import re


def b36(x: int) -> str:
    """Encode int as base36 (Rust BigUint::to_str_radix(36) compat)."""
    if x == 0:
        return "0"
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = []
    n = x
    while n:
        n, r = divmod(n, 36)
        out.append(alphabet[r])
    return "".join(reversed(out))


def from_b36(s: str) -> int:
    return int(s, 36)


# Channel for protocol-level send.
def cmd_msg(channel: str, payload: str) -> str:
    return f"MSG {channel} {payload}"


def cmd_dm(user: str, payload: str) -> str:
    return f"MSG @{user} {payload}"


# Parse the broadcast COMMITMENTS msg payload
def parse_commitments(payload: str):
    # "COMMITMENTS <ident> <q36> <g36> <c0,c1,...> <u1,u2,...>"
    parts = payload.split(" ")
    assert parts[0] == "COMMITMENTS"
    ident = parts[1]
    q = from_b36(parts[2])
    g = from_b36(parts[3])
    commits = [from_b36(x) for x in parts[4].split(",")]
    users = parts[5].split(",")
    return dict(ident=ident, q=q, g=g, commits=commits, users=users)


def parse_share(payload: str):
    # "SHARE <ident> <key> <value>"
    parts = payload.split(" ")
    assert parts[0] == "SHARE"
    return dict(ident=parts[1], key=int(parts[2]), value=from_b36(parts[3]))


def parse_recomm(payload: str):
    parts = payload.split(" ", 3)
    assert parts[0] == "RECOMM"
    ident = parts[1]
    nonce = int(parts[2])
    rest = parts[3] if len(parts) > 3 else ""
    sub = rest.split(" ", 1)[0]
    return dict(ident=ident, nonce=nonce, sub=sub, raw=rest)


def fmt_commitments(ident, q, g, commits, users):
    cs = ",".join(b36(c) for c in commits)
    us = ",".join(users)
    return f"COMMITMENTS {ident} {b36(q)} {b36(g)} {cs} {us}"


def fmt_share(ident, key, value):
    return f"SHARE {ident} {key} {b36(value)}"


def fmt_release(ident):
    return f"RELEASE {ident}"


def fmt_recomm(ident, nonce, sub):
    return f"RECOMM {ident} {nonce} {sub}"


def fmt_propose():
    return "PROPOSE"


def fmt_abort(blame):
    return f"JACCUSE {blame}"


def fmt_nuc(commit):
    return f"NUC {b36(commit)}"


def fmt_nur(proposed_share):
    return f"NUR {proposed_share}"


def fmt_begin(user, initiator, q, g, old_users):
    us = ",".join(old_users)
    return f"BEGIN {user} {initiator} {b36(q)} {b36(g)} {us}"


def fmt_ngc(key, r_commits, n_commits):
    rs = ",".join(b36(x) for x in r_commits)
    ns = ",".join(b36(x) for x in n_commits)
    return f"NGC {key} {rs} {ns}"


def fmt_ngs(from_key, key, value, is_n):
    return f"NGS {from_key} {key} {b36(value)} {'N' if is_n else 'R'}"


def fmt_br(key, value):
    return f"BR {key} {b36(value)}"


def fmt_pr(t):
    return f"PR {b36(t)}"


# Crypto helpers
def is_share_valid(q, g, commits, k, v):
    p = 2 * q + 1
    lhs = pow(g, v, p)
    rhs = 1
    for i, c in enumerate(commits):
        rhs = (rhs * pow(c, pow(k, i), p)) % p
    return lhs == rhs


def verify_share_from_commits(q, g, commits, k, v):
    return is_share_valid(q, g, commits, k, v)


# Lagrange at 0 modulo prime q
def lagrange_at0(points, q):
    # points: list of (xi, yi)
    s = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % q
            den = (den * (xi - xj)) % q
        s = (s + yi * num * pow(den, -1, q)) % q
    return s
