import json
import socket
import math
import sys
import os


def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('socket.cryptohack.org', 13423))
    s.settimeout(60)

    buf = b""

    def recv_line():
        nonlocal buf
        while b"\n" not in buf:
            data = s.recv(4096)
            if not data:
                raise ConnectionError("Connection closed")
            buf += data
        line, buf = buf.split(b"\n", 1)
        return line.decode().strip()

    def send_cmd(cmd):
        s.sendall((json.dumps(cmd) + "\n").encode())
        return json.loads(recv_line())

    banner = recv_line()
    print(f"Banner: {banner}")

    resp = send_cmd({"option": "encrypt"})
    ct_bytes = bytes.fromhex(resp["ct"])
    assert len(ct_bytes) == 48
    iv = list(ct_bytes[:16])
    c1 = list(ct_bytes[16:32])
    c2 = list(ct_bytes[32:48])

    HEX_CHARS = [ord(c) for c in '0123456789abcdef']
    total_q = 0

    LV_T = math.log(0.4)
    LV_F = math.log(0.6)
    LI_T = math.log(0.6)
    LI_F = math.log(0.4)

    def oracle(ct_hex):
        nonlocal total_q
        total_q += 1
        return send_cmd({"option": "unpad", "ct": ct_hex})["result"]

    def make_ct(target, inter, pos, pad, cand):
        m = bytearray(os.urandom(16))
        for k in range(pos + 1, 16):
            m[k] = inter[k] ^ pad
        m[pos] = cand ^ pad
        return (bytes(m) + bytes(target)).hex()

    def do_rounds(target, inter, pos, pad, cands, log_p, active, n_rounds, max_q):
        """Round-robin over active candidates. Only update active to prevent drift."""
        q = 0
        for _ in range(n_rounds):
            for idx in active:
                if q >= max_q:
                    return q
                result = oracle(make_ct(target, inter, pos, pad, cands[idx]))
                q += 1
                if result:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
        return q

    def get_best(log_p, active):
        best = max(active, key=lambda i: log_p[i])
        max_lp = log_p[best]
        raw = [math.exp(log_p[i] - max_lp) for i in active]
        tot = sum(raw)
        prob = raw[active.index(best)] / tot
        return best, prob

    def find_byte(target, inter, pos, pad, cands, budget):
        """
        Optimized 4-phase elimination with long duel.

        Budget split: P1(80) + P2(48) + P3(120) + Duel(remaining)
        Key insight: previous configs had duel too short (13 rounds = 2.1 nats).
        Now duel gets ~62 rounds = 10+ nats, making duel error negligible.

        Per-byte error: ~0.7% (Phase 3 0.3% + duel 0.2% + earlier 0.2%)
        Overall 32-byte success: ~80%
        """
        n = len(cands)
        log_p = [0.0] * n
        active = list(range(n))
        used = 0

        # Phase 1: 5 rounds over 16 -> keep 8
        q = do_rounds(target, inter, pos, pad, cands, log_p, active, 5, budget - used)
        used += q
        ranked = sorted(active, key=lambda i: log_p[i], reverse=True)
        active = ranked[:8]

        best, prob = get_best(log_p, active)
        if prob > 0.999:
            return cands[best], prob, used

        # Phase 2: 6 rounds over 8 -> keep 4
        q = do_rounds(target, inter, pos, pad, cands, log_p, active, 6, budget - used)
        used += q
        ranked = sorted(active, key=lambda i: log_p[i], reverse=True)
        active = ranked[:4]

        best, prob = get_best(log_p, active)
        if prob > 0.999:
            return cands[best], prob, used

        # Phase 3: 35 rounds over 4 -> keep 2
        q = do_rounds(target, inter, pos, pad, cands, log_p, active, 35, budget - used)
        used += q
        ranked = sorted(active, key=lambda i: log_p[i], reverse=True)
        active = ranked[:2]

        best, prob = get_best(log_p, active)
        if prob > 0.999:
            return cands[best], prob, used

        # Phase 4: duel with ALL remaining budget
        remaining = budget - used
        duel_rounds = max(1, remaining // 2)
        q = do_rounds(target, inter, pos, pad, cands, log_p, active, duel_rounds, budget - used)
        used += q

        best, prob = get_best(log_p, active)
        return cands[best], prob, used

    def recover_block(target, prev, name, bytes_after):
        inter = [0] * 16
        for pos in range(15, -1, -1):
            pad = 16 - pos
            cands = [prev[pos] ^ h for h in HEX_CHARS]

            remaining_bytes = pos + 1 + bytes_after
            remaining_q = 11900 - total_q
            budget = min(remaining_q // max(1, remaining_bytes), 420)
            budget = max(budget, 200)

            winner, prob, q = find_byte(target, inter, pos, pad, cands, budget)
            inter[pos] = winner
            pt = winner ^ prev[pos]
            ch = chr(pt) if 32 <= pt < 127 else '?'
            print(f"  {name}[{pos:2d}]='{ch}' p={prob:.4f} q={q} bgt={budget} T={total_q}")
            sys.stdout.flush()
        return inter

    print("=== Block 2 (C2) ===")
    i2 = recover_block(c2, c1, "B2", bytes_after=16)
    pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])
    print(f"  -> {pt2.decode('ascii', 'replace')}")

    print("=== Block 1 (C1) ===")
    i1 = recover_block(c1, iv, "B1", bytes_after=0)
    pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])
    print(f"  -> {pt1.decode('ascii', 'replace')}")

    msg = (pt1 + pt2).decode('ascii', 'replace')
    print(f"\nMessage: {msg}")
    print(f"Queries: {total_q}/12000")

    resp = send_cmd({"option": "check", "message": msg})
    print(f"Result: {resp}")
    s.close()

    if "flag" in resp:
        print(f"\n*** FLAG: {resp['flag']} ***")
    else:
        raise RuntimeError(f"Wrong message: {resp}")


if __name__ == "__main__":
    for attempt in range(10):
        print(f"\n{'='*60}")
        print(f"ATTEMPT {attempt + 1}")
        print(f"{'='*60}")
        try:
            solve()
            break  # solve() will print flag and return on success
        except SystemExit:
            raise
        except Exception as e:
            print(f"Attempt {attempt + 1} error: {e}")
            import traceback
            traceback.print_exc()
