import json
import socket
import math
import sys
import os
import traceback


HOST = 'socket.cryptohack.org'
PORT = 13423
MAX_TOTAL_Q = 12000
SAFE_TOTAL_Q = 11880  # leave a little room for final check / jitter

HEX_CHARS = [ord(c) for c in '0123456789abcdef']

# Noisy oracle model from the challenge.
LV_T = math.log(0.4)  # valid candidate, observed True
LV_F = math.log(0.6)  # valid candidate, observed False
LI_T = math.log(0.6)  # invalid candidate, observed True
LI_F = math.log(0.4)  # invalid candidate, observed False


class RetryAttempt(RuntimeError):
    pass


class OracleClient:
    def __init__(self, host=HOST, port=PORT):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.s.settimeout(60)
        self.buf = b''
        self.total_q = 0
        self.banner = self.recv_line()
        print(f"Banner: {self.banner}")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def recv_line(self):
        while b"\n" not in self.buf:
            data = self.s.recv(4096)
            if not data:
                raise ConnectionError("Connection closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode().strip()

    def send_cmd(self, cmd):
        self.s.sendall((json.dumps(cmd) + "\n").encode())
        return json.loads(self.recv_line())

    def encrypt(self):
        return self.send_cmd({"option": "encrypt"})

    def oracle(self, ct_hex):
        self.total_q += 1
        return self.send_cmd({"option": "unpad", "ct": ct_hex})["result"]

    def check(self, message):
        return self.send_cmd({"option": "check", "message": message})


def make_ct(target, inter, pos, pad, cand):
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand ^ pad
    return (bytes(m) + bytes(target)).hex()


def probs_from_logps(log_p, active):
    mx = max(log_p[i] for i in active)
    vals = [math.exp(log_p[i] - mx) for i in active]
    tot = sum(vals)
    ranked = sorted(
        ((idx, vals[pos] / tot) for pos, idx in enumerate(active)),
        key=lambda x: x[1],
        reverse=True,
    )
    return ranked


def do_chunk(client, target, inter, pos, pad, cands, log_p, active, rounds, max_q):
    q = 0
    for _ in range(rounds):
        for idx in list(active):
            if q >= max_q or client.total_q >= SAFE_TOTAL_Q:
                return q
            result = client.oracle(make_ct(target, inter, pos, pad, cands[idx]))
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


def maybe_prune(log_p, active, keep, min_gap_nats):
    ranked = sorted(active, key=lambda i: log_p[i], reverse=True)
    if len(ranked) <= keep:
        return ranked
    boundary_gap = log_p[ranked[keep - 1]] - log_p[ranked[keep]]
    if boundary_gap >= min_gap_nats:
        return ranked[:keep]
    return ranked


def find_byte(client, target, inter, pos, pad, cands, budget):
    n = len(cands)
    log_p = [0.0] * n
    active = list(range(n))
    used = 0

    # Much gentler elimination than the original 16->8->4->2.
    # We keep extra candidates alive longer to reduce valid-candidate death.
    plan = [
        # rounds, keep, min gap to allow prune
        (2, 12, 0.15),
        (3, 8, 0.25),
        (5, 5, 0.40),
        (8, 3, 0.55),
    ]

    for rounds, keep, min_gap in plan:
        if used >= budget or len(active) <= keep:
            break
        q = do_chunk(client, target, inter, pos, pad, cands, log_p, active, rounds, budget - used)
        used += q
        active = maybe_prune(log_p, active, keep, min_gap)

        ranked_probs = probs_from_logps(log_p, active)
        best_idx, best_prob = ranked_probs[0]
        second_prob = ranked_probs[1][1] if len(ranked_probs) > 1 else 0.0

        # Very confident.
        if best_prob >= 0.995:
            return cands[best_idx], best_prob, used

        # Strong sign that the path is collapsing. Restart instead of wasting budget.
        if used >= min(140, budget // 2) and best_prob <= 0.52:
            raise RetryAttempt(f"posterior collapse at pos={pos}, p={best_prob:.4f}")

        # If top two are nearly tied late in the stage, keep more candidates alive.
        if len(active) == keep and best_prob - second_prob < 0.04 and keep > 3:
            active = sorted(active, key=lambda i: log_p[i], reverse=True)[: min(len(active), keep + 1)]

    # Final duel/truel: keep top 3 as long as possible, not top 2.
    active = sorted(active, key=lambda i: log_p[i], reverse=True)[:3]
    while used < budget and client.total_q < SAFE_TOTAL_Q:
        chunk_rounds = max(1, min(12, (budget - used) // max(1, len(active))))
        q = do_chunk(client, target, inter, pos, pad, cands, log_p, active, chunk_rounds, budget - used)
        used += q
        ranked_probs = probs_from_logps(log_p, active)
        best_idx, best_prob = ranked_probs[0]
        second_prob = ranked_probs[1][1] if len(ranked_probs) > 1 else 0.0

        if best_prob >= 0.985:
            return cands[best_idx], best_prob, used

        # Late-stage collapse: restart early.
        if used >= int(budget * 0.75) and best_prob <= 0.55:
            raise RetryAttempt(f"late posterior collapse at pos={pos}, p={best_prob:.4f}")

        # Only prune from 3 -> 2 if the third candidate is clearly behind.
        if len(active) == 3:
            third_prob = ranked_probs[2][1]
            if third_prob < 0.08 and (best_prob - second_prob) > 0.05:
                active = [idx for idx, _ in ranked_probs[:2]]

        # If top two are still glued together near the end, keep truel going.
        if len(active) == 2 and used >= int(budget * 0.9) and abs(best_prob - second_prob) < 0.06:
            raise RetryAttempt(f"coinflip at pos={pos}, p={best_prob:.4f}")

        # No more progress possible.
        if q == 0:
            break

    ranked_probs = probs_from_logps(log_p, active)
    best_idx, best_prob = ranked_probs[0]
    if best_prob <= 0.58:
        raise RetryAttempt(f"final posterior too low at pos={pos}, p={best_prob:.4f}")
    return cands[best_idx], best_prob, used


def per_byte_budget(total_q, pos, bytes_after):
    remaining_bytes = pos + 1 + bytes_after
    remaining_q = max(0, SAFE_TOTAL_Q - total_q)

    # Conservative base budget so one shaky byte does not poison the run.
    base = remaining_q // max(1, remaining_bytes)
    base = max(base, 220)

    # Spend a bit more on later-recovered bytes (higher pos, especially near padding edge).
    if pos >= 12:
        base += 80
    elif pos >= 8:
        base += 40

    # Never starve the remaining bytes.
    return min(base, 520)


def recover_block(client, target, prev, name, bytes_after):
    inter = [0] * 16
    for pos in range(15, -1, -1):
        pad = 16 - pos
        cands = [prev[pos] ^ h for h in HEX_CHARS]
        budget = per_byte_budget(client.total_q, pos, bytes_after)

        winner, prob, q = find_byte(client, target, inter, pos, pad, cands, budget)
        inter[pos] = winner
        pt = winner ^ prev[pos]
        ch = chr(pt) if 32 <= pt < 127 else '?'
        print(f"  {name}[{pos:2d}]='{ch}' p={prob:.4f} q={q} bgt={budget} T={client.total_q}")
        sys.stdout.flush()

    return inter


def solve_once():
    client = OracleClient()
    try:
        resp = client.encrypt()
        ct_bytes = bytes.fromhex(resp['ct'])
        assert len(ct_bytes) == 48
        iv = list(ct_bytes[:16])
        c1 = list(ct_bytes[16:32])
        c2 = list(ct_bytes[32:48])

        print("=== Block 2 (C2) ===")
        i2 = recover_block(client, c2, c1, 'B2', bytes_after=16)
        pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])
        print(f"  -> {pt2.decode('ascii', 'replace')}")

        print("=== Block 1 (C1) ===")
        i1 = recover_block(client, c1, iv, 'B1', bytes_after=0)
        pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])
        print(f"  -> {pt1.decode('ascii', 'replace')}")

        msg = (pt1 + pt2).decode('ascii', 'replace')
        print(f"\nMessage: {msg}")
        print(f"Queries: {client.total_q}/{MAX_TOTAL_Q}")

        resp = client.check(msg)
        print(f"Result: {resp}")
        if 'flag' in resp:
            print(f"\n*** FLAG: {resp['flag']} ***")
            return True
        raise RuntimeError(f"Wrong message: {resp}")
    finally:
        client.close()


def main():
    for attempt in range(1, 11):
        print("\n" + "=" * 60)
        print(f"ATTEMPT {attempt}")
        print("=" * 60)
        try:
            if solve_once():
                return
        except RetryAttempt as e:
            print(f"Attempt {attempt} restart: {e}")
        except SystemExit:
            raise
        except Exception as e:
            print(f"Attempt {attempt} error: {e}")
            traceback.print_exc()


if __name__ == '__main__':
    main()
