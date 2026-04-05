import json
import math
import os
import socket
import sys
import traceback
from typing import List, Tuple

HOST = 'socket.cryptohack.org'
PORT = 13423
MAX_QUERIES = 12000
MAX_ATTEMPTS = 10

HEX_CHARS = [ord(c) for c in '0123456789abcdef']
LOG_V_T = math.log(0.4)  # observed True if candidate is VALID
LOG_V_F = math.log(0.6)  # observed False if candidate is VALID
LOG_I_T = math.log(0.6)  # observed True if candidate is INVALID
LOG_I_F = math.log(0.4)  # observed False if candidate is INVALID


def logsumexp(values: List[float]) -> float:
    m = max(values)
    return m + math.log(sum(math.exp(v - m) for v in values))


class OracleSession:
    def __init__(self) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((HOST, PORT))
        self.s.settimeout(60)
        self.buf = b''
        self.total_q = 0
        banner = self.recv_line()
        print(f"Banner: {banner}")
        sys.stdout.flush()

    def close(self) -> None:
        try:
            self.s.close()
        except Exception:
            pass

    def recv_line(self) -> str:
        while b'\n' not in self.buf:
            data = self.s.recv(4096)
            if not data:
                raise ConnectionError('Connection closed')
            self.buf += data
        line, self.buf = self.buf.split(b'\n', 1)
        return line.decode().strip()

    def send_cmd(self, cmd: dict) -> dict:
        self.s.sendall((json.dumps(cmd) + '\n').encode())
        return json.loads(self.recv_line())

    def encrypt(self) -> bytes:
        resp = self.send_cmd({'option': 'encrypt'})
        ct = bytes.fromhex(resp['ct'])
        if len(ct) != 48:
            raise ValueError(f'Unexpected ciphertext length: {len(ct)}')
        return ct

    def oracle(self, ct_hex: str) -> bool:
        self.total_q += 1
        return self.send_cmd({'option': 'unpad', 'ct': ct_hex})['result']

    def check(self, message: str) -> dict:
        return self.send_cmd({'option': 'check', 'message': message})


def make_ct(target: List[int], inter: List[int], pos: int, pad: int, cand_inter: int) -> str:
    """Build a 2-block ciphertext for probing one byte.

    target: ciphertext block being attacked (16 ints)
    inter: already recovered intermediate bytes for positions > pos
    cand_inter: candidate intermediate byte for this position
    """
    m = bytearray(os.urandom(16))
    for k in range(pos + 1, 16):
        m[k] = inter[k] ^ pad
    m[pos] = cand_inter ^ pad
    return (bytes(m) + bytes(target)).hex()


def candidate_llr(true_count: int, total_count: int) -> float:
    """Log-likelihood ratio: log P(data|valid) - log P(data|invalid)."""
    false_count = total_count - true_count
    return true_count * (LOG_V_T - LOG_I_T) + false_count * (LOG_V_F - LOG_I_F)


def posterior_from_llrs(llrs: List[float], active: List[int]) -> Tuple[int, float, List[float]]:
    act_llrs = [llrs[i] for i in active]
    z = logsumexp(act_llrs)
    probs = [math.exp(v - z) for v in act_llrs]
    best_local = max(range(len(active)), key=lambda idx: act_llrs[idx])
    best_idx = active[best_local]
    return best_idx, probs[best_local], probs


def sample_candidate(session: OracleSession, target: List[int], inter: List[int], pos: int,
                     pad: int, cand_inter: int, reps: int) -> Tuple[int, int]:
    true_count = 0
    for _ in range(reps):
        if session.oracle(make_ct(target, inter, pos, pad, cand_inter)):
            true_count += 1
    return true_count, reps


def find_byte_independent(
    session: OracleSession,
    target: List[int],
    prev: List[int],
    inter: List[int],
    pos: int,
    bytes_after: int,
) -> Tuple[int, float, int]:
    """Recover one intermediate byte using independent per-candidate LLRs.

    Strategy:
    1) Probe all 16 candidates a few times.
    2) Keep shrinking active set while preserving evidence per candidate.
    3) Spend the rest of the budget on top-2 / top-3 candidates only.
    4) If confidence remains poor, fail this session early.
    """
    pad = 16 - pos
    cands = [prev[pos] ^ h for h in HEX_CHARS]  # candidate intermediate bytes

    remaining_bytes = pos + 1 + bytes_after
    remaining_q = MAX_QUERIES - 100 - session.total_q  # keep safety margin
    if remaining_q < 120:
        raise RuntimeError('Not enough remaining query budget')

    # Slightly front-load budget because one bad byte ruins the rest.
    budget = max(180, min(remaining_q // max(1, remaining_bytes), 420))

    # Per-candidate evidence.
    n = [0] * len(cands)
    t = [0] * len(cands)
    llr = [0.0] * len(cands)
    used = 0
    active = list(range(len(cands)))

    def refresh_scores() -> None:
        for i in range(len(cands)):
            llr[i] = candidate_llr(t[i], n[i]) if n[i] else 0.0

    def sample_active(indices: List[int], reps: int) -> None:
        nonlocal used
        for idx in indices:
            if used + reps > budget:
                break
            true_count, total_count = sample_candidate(session, target, inter, pos, pad, cands[idx], reps)
            t[idx] += true_count
            n[idx] += total_count
            used += total_count
        refresh_scores()

    # Stage 1: coarse scan of all 16
    sample_active(active, 4)  # 64 queries
    active = sorted(active, key=lambda i: llr[i], reverse=True)[:10]

    # Stage 2: refine top 10 -> top 6
    sample_active(active, 4)  # up to 40 queries
    active = sorted(active, key=lambda i: llr[i], reverse=True)[:6]

    # Stage 3: refine top 6 -> top 3
    sample_active(active, 8)  # up to 48 queries
    active = sorted(active, key=lambda i: llr[i], reverse=True)[:3]

    # Final stage: allocate remaining budget adaptively among top 3.
    # Spend more on uncertain candidates with low samples / close scores.
    while used + len(active) <= budget:
        best_idx, best_prob, probs = posterior_from_llrs(llr, active)
        sorted_active = sorted(active, key=lambda i: llr[i], reverse=True)
        gap = llr[sorted_active[0]] - llr[sorted_active[1]] if len(sorted_active) >= 2 else 999.0

        # Strong enough confidence for this byte.
        if best_prob >= 0.92 and gap >= 2.0 and min(n[i] for i in active) >= 20:
            break

        # If one candidate is clearly bad, reduce top 3 -> top 2.
        if len(active) == 3:
            third_gap = llr[sorted_active[1]] - llr[sorted_active[2]]
            if third_gap >= 2.5 and min(n[i] for i in sorted_active[:2]) >= 16:
                active = sorted_active[:2]
                continue

        # Sample the weakest-supported promising candidate first.
        if len(active) == 3:
            # Prioritize candidates with the fewest samples, breaking ties by higher llr.
            idx = min(active, key=lambda i: (n[i], -llr[i]))
        else:
            # For top-2, alternate toward the less certain candidate.
            idx = min(active, key=lambda i: (llr[i], n[i]))

        sample_active([idx], 2)

    best_idx, best_prob, probs = posterior_from_llrs(llr, active)
    winner = cands[best_idx]

    # Session-collapse indicators: confidence too low or too many nearly-equal candidates.
    sorted_active = sorted(active, key=lambda i: llr[i], reverse=True)
    if len(sorted_active) >= 2:
        final_gap = llr[sorted_active[0]] - llr[sorted_active[1]]
    else:
        final_gap = 999.0

    # Very weak evidence means continuing will likely cascade into garbage.
    if best_prob < 0.68 or final_gap < 0.75:
        raise RuntimeError(
            f'Low-confidence byte at pos={pos}: p={best_prob:.4f}, gap={final_gap:.3f}, used={used}, active={len(active)}'
        )

    return winner, best_prob, used


def recover_block(session: OracleSession, target: List[int], prev: List[int], name: str, bytes_after: int) -> List[int]:
    inter = [0] * 16
    for pos in range(15, -1, -1):
        winner, prob, q_used = find_byte_independent(session, target, prev, inter, pos, bytes_after)
        inter[pos] = winner
        pt = winner ^ prev[pos]
        ch = chr(pt) if 32 <= pt < 127 else '?'
        print(f"  {name}[{pos:2d}]='{ch}' p={prob:.4f} q={q_used} T={session.total_q}")
        sys.stdout.flush()
    return inter


def solve_once() -> None:
    session = OracleSession()
    try:
        ct_bytes = session.encrypt()
        iv = list(ct_bytes[:16])
        c1 = list(ct_bytes[16:32])
        c2 = list(ct_bytes[32:48])

        print('=== Block 2 (C2) ===')
        i2 = recover_block(session, c2, c1, 'B2', bytes_after=16)
        pt2 = bytes([i2[i] ^ c1[i] for i in range(16)])
        print(f"  -> {pt2.decode('ascii', 'replace')}")

        print('=== Block 1 (C1) ===')
        i1 = recover_block(session, c1, iv, 'B1', bytes_after=0)
        pt1 = bytes([i1[i] ^ iv[i] for i in range(16)])
        print(f"  -> {pt1.decode('ascii', 'replace')}")

        msg = (pt1 + pt2).decode('ascii', 'replace')
        print(f"\nMessage: {msg}")
        print(f"Queries: {session.total_q}/{MAX_QUERIES}")

        resp = session.check(msg)
        print(f"Result: {resp}")
        if 'flag' in resp:
            print(f"\n*** FLAG: {resp['flag']} ***")
            return
        raise RuntimeError(f'Wrong message: {resp}')
    finally:
        session.close()


if __name__ == '__main__':
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print('\n' + '=' * 60)
        print(f'ATTEMPT {attempt}')
        print('=' * 60)
        try:
            solve_once()
            break
        except SystemExit:
            raise
        except Exception as exc:
            print(f'Attempt {attempt} error: {exc}')
            traceback.print_exc()
